//! UVM observability service.
//!
//! This bounded context owns VM-level performance attestations and failure
//! reporting required by UVM acceptance gates.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use http::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{PlatformError, RequestContext, Result, sha256_hex};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{AuditLog, DocumentStore, DurableOutbox};
use uhost_types::{
    AuditActor, AuditId, EventHeader, EventPayload, OwnershipScope, PlatformEvent,
    ResourceLifecycleState, ResourceMetadata, ServiceEvent, UvmBenchmarkBaselineId,
    UvmBenchmarkCampaignId, UvmBenchmarkResultId, UvmClaimDecisionId, UvmFailureReportId,
    UvmHostEvidenceId, UvmInstanceId, UvmPerfAttestationId, UvmRuntimeSessionId,
};
use uhost_uvm::{
    ClaimEvidenceMode, ClaimTier, HostClass, HostClassEnvironment, HostPlatform, MeasurementMode,
    UvmCompatibilityAssessment, UvmCompatibilityEvidenceSource, UvmPortabilityAssessment,
    UvmPortabilityAssessmentSource, UvmPortabilityAssessmentUnavailableReason,
};

/// Measured UVM performance attestation for one workload class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmPerfAttestationRecord {
    /// Attestation identifier.
    pub id: UvmPerfAttestationId,
    /// Instance identifier.
    pub instance_id: UvmInstanceId,
    /// Workload class key (`general`, `cpu_intensive`, `io_intensive`, etc.).
    pub workload_class: String,
    /// Evidence-gated claim tier for this workload attestation.
    #[serde(default = "default_claim_tier_key")]
    pub claim_tier: String,
    /// Evidence mode for the claim tier.
    #[serde(default = "default_claim_evidence_mode_key")]
    pub claim_evidence_mode: String,
    /// Measured CPU overhead percentage versus native baseline.
    pub cpu_overhead_pct: u16,
    /// Measured memory overhead percentage versus native baseline.
    pub memory_overhead_pct: u16,
    /// Measured block IO latency overhead percentage versus native baseline.
    pub block_io_latency_overhead_pct: u16,
    /// Measured network latency overhead percentage versus native baseline.
    pub network_latency_overhead_pct: u16,
    /// Measured jitter percentage.
    pub jitter_pct: u16,
    /// Whether this sample is within the native-indistinguishable envelope.
    pub native_indistinguishable: bool,
    /// Measurement timestamp.
    pub measured_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// UVM failure report for incident and forensic workflows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmFailureReportRecord {
    /// Failure report identifier.
    pub id: UvmFailureReportId,
    /// Optional instance identifier when this is instance-scoped.
    pub instance_id: Option<UvmInstanceId>,
    /// Failure category.
    pub category: String,
    /// Severity.
    pub severity: String,
    /// Exit reason or fault summary.
    pub summary: String,
    /// Whether automatic recovery succeeded.
    pub recovered: bool,
    /// Whether forensic capture was requested.
    pub forensic_capture_requested: bool,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Stored host evidence used to decide whether a performance claim may be published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmHostEvidenceRecord {
    /// Host evidence identifier.
    pub id: UvmHostEvidenceId,
    /// Evidence mode attached to the host observation.
    pub evidence_mode: String,
    /// Host platform key.
    pub host_platform: String,
    /// Shared host-class key for this observation.
    #[serde(default)]
    pub host_class: String,
    /// Canonical key used to join evidence on host class alone.
    #[serde(default)]
    pub host_class_evidence_key: String,
    /// Execution environment key.
    pub execution_environment: String,
    /// Whether hardware virtualization is available.
    pub hardware_virtualization: bool,
    /// Whether nested virtualization is available.
    pub nested_virtualization: bool,
    /// Whether QEMU is available.
    pub qemu_available: bool,
    /// Optional operator note.
    pub note: Option<String>,
    /// Collection timestamp.
    pub collected_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Read-only observe artifact derived from a runtime preflight witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmPreflightEvidenceArtifact {
    /// Stable artifact identifier. Reuses the runtime-preflight identifier.
    pub id: AuditId,
    /// Runtime-preflight record used as the artifact source.
    pub runtime_preflight_id: AuditId,
    /// Host platform key extracted from the preflight compatibility evidence.
    pub host_platform: String,
    /// Shared host-class key extracted from the preflight compatibility evidence.
    pub host_class: String,
    /// Canonical key used to join preflight evidence on host class alone.
    pub host_class_evidence_key: String,
    /// Evidence mode attached to the node capability evidence row when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_mode: Option<String>,
    /// Claim tier carried by the linked runtime preflight.
    #[serde(default = "default_claim_tier_key")]
    pub claim_tier: String,
    /// Guest architecture evaluated by the preflight.
    pub guest_architecture: String,
    /// Machine family evaluated by the preflight.
    pub machine_family: String,
    /// Guest profile evaluated by the preflight.
    pub guest_profile: String,
    /// Selected backend when the preflight chose one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_backend: Option<String>,
    /// Compatibility assessment carried by the preflight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility_assessment: Option<UvmCompatibilityAssessment>,
    /// Portability assessment carried by the preflight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portability_assessment: Option<UvmPortabilityAssessment>,
    /// Artifact source timestamp copied from the preflight witness.
    pub created_at: OffsetDateTime,
}

/// Persisted claim-decision record derived from perf attestations and host evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmClaimDecisionRecord {
    /// Claim-decision identifier.
    pub id: UvmClaimDecisionId,
    /// Host evidence used for the decision when present.
    pub host_evidence_id: Option<UvmHostEvidenceId>,
    /// Authoritative runtime session linked to this decision when current lineage is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_session_id: Option<UvmRuntimeSessionId>,
    /// Node runtime-preflight or migration-preflight record linked for portability evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_preflight_id: Option<AuditId>,
    /// Highest publishable claim tier after evidence and benchmark sufficiency gating.
    pub highest_claim_tier: String,
    /// Highest observed claim tier before benchmark sufficiency demotions are applied.
    #[serde(default)]
    pub observed_highest_claim_tier: String,
    /// Highest claim tier fully supported by the current benchmark proof envelope.
    #[serde(default)]
    pub benchmark_claim_tier_ceiling: String,
    /// Benchmark scenarios currently backed by direct proof for this claim decision.
    #[serde(default)]
    pub benchmark_ready_scenarios: Vec<String>,
    /// Effective publication status for the current evidence envelope.
    pub claim_status: String,
    /// Whether the native-indistinguishable threshold itself passed.
    pub native_indistinguishable_status: bool,
    /// Number of prohibited claims currently present.
    pub prohibited_claim_count: u32,
    /// Missing workload classes blocking broader claims.
    pub missing_required_workload_classes: Vec<String>,
    /// Workload classes currently failing the native envelope.
    pub failing_workload_classes: Vec<String>,
    /// Optional structured portability assessment that scoped this reporting decision.
    #[serde(default)]
    pub portability_assessment: Option<UvmPortabilityAssessment>,
    /// Provenance marker explaining which portability source won precedence.
    #[serde(default)]
    pub portability_assessment_source: UvmPortabilityAssessmentSource,
    /// Stable reason describing why authoritative runtime lineage could not surface
    /// a portability assessment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portability_assessment_unavailable_reason:
        Option<UvmPortabilityAssessmentUnavailableReason>,
    /// Decision timestamp.
    pub decided_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NodeRuntimePreflightPortabilityRecord {
    id: AuditId,
    #[serde(default)]
    guest_architecture: String,
    #[serde(default)]
    machine_family: String,
    #[serde(default)]
    guest_profile: String,
    #[serde(default = "default_claim_tier_key")]
    claim_tier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selected_backend: Option<String>,
    #[serde(default)]
    compatibility_assessment: Option<UvmCompatibilityAssessment>,
    #[serde(default)]
    portability_assessment: Option<UvmPortabilityAssessment>,
    #[serde(default = "default_observe_timestamp")]
    created_at: OffsetDateTime,
    #[serde(default, flatten)]
    extra_fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NodeRuntimeSessionIntentLineageRecord {
    runtime_session_id: UvmRuntimeSessionId,
    instance_id: UvmInstanceId,
    #[serde(default)]
    first_placement_portability_assessment: Option<UvmPortabilityAssessment>,
    #[serde(default)]
    last_portability_preflight_id: Option<AuditId>,
    #[serde(default)]
    created_at: Option<OffsetDateTime>,
    #[serde(default, flatten)]
    extra_fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NodeRuntimeSessionPresenceRecord {
    id: UvmRuntimeSessionId,
    instance_id: UvmInstanceId,
    #[serde(default, flatten)]
    extra_fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeLineagePortabilityResolution {
    instance_id: UvmInstanceId,
    runtime_session_id: UvmRuntimeSessionId,
    runtime_preflight_id: Option<AuditId>,
    portability_assessment: UvmPortabilityAssessment,
    source: UvmPortabilityAssessmentSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedClaimDecisionPortability {
    runtime_session_id: Option<UvmRuntimeSessionId>,
    runtime_preflight_id: Option<AuditId>,
    portability_assessment: Option<UvmPortabilityAssessment>,
    source: UvmPortabilityAssessmentSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopedImagePublicationScope {
    host_class: String,
    host_class_evidence_key: String,
    region: Option<String>,
    cell: Option<String>,
    claim_tier: String,
    selected_backend: Option<String>,
    machine_family: String,
    guest_profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ResolvedPublicationScope {
    host_class_evidence_key: Option<String>,
    region: Option<String>,
    cell: Option<String>,
    backend: Option<String>,
}

impl ResolvedPublicationScope {
    fn from_scoped_image(scope: ScopedImagePublicationScope) -> Self {
        Self {
            host_class_evidence_key: Some(scope.host_class_evidence_key),
            region: scope.region,
            cell: scope.cell,
            backend: scope.selected_backend,
        }
    }

    fn apply_metadata_annotations(&self, metadata: &mut ResourceMetadata) -> bool {
        let mut changed = false;
        for (key, value) in [
            (
                "publication_scope_host_class_evidence_key",
                self.host_class_evidence_key.as_deref(),
            ),
            ("publication_scope_region", self.region.as_deref()),
            ("publication_scope_cell", self.cell.as_deref()),
            ("publication_scope_backend", self.backend.as_deref()),
        ] {
            let Some(value) = value else {
                continue;
            };
            if metadata.annotations.get(key).map(String::as_str) != Some(value) {
                metadata
                    .annotations
                    .insert(String::from(key), value.to_owned());
                changed = true;
            }
        }
        changed
    }
}

/// Persisted benchmark campaign for the first benchmark-program slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmBenchmarkCampaignRecord {
    /// Benchmark campaign identifier.
    pub id: UvmBenchmarkCampaignId,
    /// Human-readable campaign name.
    pub name: String,
    /// Target kind (`host`, `ubuntu_22_04_vm`, `apple_mac_studio_m1_pro_sim`).
    pub target: String,
    /// Workload class attached to the campaign.
    pub workload_class: String,
    /// Whether a QEMU baseline is required for this campaign.
    pub require_qemu_baseline: bool,
    /// Whether a container baseline is required for this campaign.
    pub require_container_baseline: bool,
    /// Campaign state (`draft`, `ready`).
    pub state: String,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Persisted benchmark baseline row attached to a campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmBenchmarkBaselineRecord {
    /// Benchmark baseline identifier.
    pub id: UvmBenchmarkBaselineId,
    /// Owning benchmark campaign.
    pub campaign_id: UvmBenchmarkCampaignId,
    /// Canonical host-class key for measured rows when host evidence is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_class_evidence_key: Option<String>,
    /// Workload class inherited from the owning campaign.
    #[serde(default)]
    pub workload_class: String,
    /// Scenario key this baseline may be compared against.
    #[serde(default)]
    pub scenario: String,
    /// Optional guest-run lineage key for guest-target benchmark rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_run_lineage: Option<String>,
    /// Explicit measurement mode used for comparison-lineage alignment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement_mode: Option<String>,
    /// Engine key (`software_dbt`, `qemu`, `container`).
    pub engine: String,
    /// Evidence mode for the baseline.
    pub evidence_mode: String,
    /// Whether this baseline is measured directly.
    pub measured: bool,
    /// Optional boot-time measurement in milliseconds.
    pub boot_time_ms: Option<u32>,
    /// Optional steady-state score.
    pub steady_state_score: Option<u32>,
    /// Optional control-plane p99 in milliseconds.
    pub control_plane_p99_ms: Option<u32>,
    /// Optional host evidence reference.
    pub host_evidence_id: Option<UvmHostEvidenceId>,
    /// Optional note.
    pub note: Option<String>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Persisted measured benchmark result row attached to a campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmBenchmarkResultRecord {
    /// Benchmark result identifier.
    pub id: UvmBenchmarkResultId,
    /// Owning benchmark campaign.
    pub campaign_id: UvmBenchmarkCampaignId,
    /// Canonical host-class key for measured rows when host evidence is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_class_evidence_key: Option<String>,
    /// Workload class inherited from the owning campaign.
    #[serde(default)]
    pub workload_class: String,
    /// Optional guest-run lineage key for guest-target benchmark rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_run_lineage: Option<String>,
    /// Explicit measurement mode used for comparison-lineage alignment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement_mode: Option<String>,
    /// Engine key (`software_dbt`, `qemu`, `container`).
    pub engine: String,
    /// Scenario key (`cold_boot`, `service_readiness`, etc.).
    pub scenario: String,
    /// Evidence mode for the result row.
    pub evidence_mode: String,
    /// Whether this result is measured directly.
    pub measured: bool,
    /// Measured boot-time value in milliseconds.
    pub boot_time_ms: u32,
    /// Measured steady-state score.
    pub steady_state_score: u32,
    /// Measured control-plane p99 value in milliseconds.
    pub control_plane_p99_ms: u32,
    /// Optional host evidence reference.
    pub host_evidence_id: Option<UvmHostEvidenceId>,
    /// Optional note.
    pub note: Option<String>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreatePerfAttestationRequest {
    instance_id: String,
    workload_class: String,
    claim_tier: Option<String>,
    claim_evidence_mode: Option<String>,
    cpu_overhead_pct: u16,
    memory_overhead_pct: u16,
    block_io_latency_overhead_pct: u16,
    network_latency_overhead_pct: u16,
    jitter_pct: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateFailureReportRequest {
    instance_id: Option<String>,
    category: String,
    severity: String,
    summary: String,
    recovered: bool,
    forensic_capture_requested: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateHostEvidenceRequest {
    evidence_mode: String,
    host_platform: String,
    execution_environment: String,
    hardware_virtualization: bool,
    nested_virtualization: bool,
    qemu_available: bool,
    note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateClaimDecisionRequest {
    host_evidence_id: Option<String>,
    runtime_preflight_id: Option<String>,
    #[serde(default)]
    portability_assessment: Option<UvmPortabilityAssessment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateBenchmarkCampaignRequest {
    name: String,
    target: String,
    workload_class: String,
    require_qemu_baseline: Option<bool>,
    require_container_baseline: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateBenchmarkBaselineRequest {
    campaign_id: String,
    engine: String,
    scenario: Option<String>,
    guest_run_lineage: Option<String>,
    measurement_mode: Option<String>,
    evidence_mode: String,
    measured: bool,
    boot_time_ms: Option<u32>,
    steady_state_score: Option<u32>,
    control_plane_p99_ms: Option<u32>,
    host_evidence_id: Option<String>,
    note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateBenchmarkResultRequest {
    campaign_id: String,
    engine: String,
    scenario: String,
    guest_run_lineage: Option<String>,
    measurement_mode: Option<String>,
    evidence_mode: String,
    measured: bool,
    boot_time_ms: u32,
    steady_state_score: u32,
    control_plane_p99_ms: u32,
    host_evidence_id: Option<String>,
    note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BenchmarkMeasurementScope {
    host_class_evidence_key: String,
    workload_class: String,
    scenario: String,
    engine: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BenchmarkComparisonLineage {
    guest_run_lineage: Option<String>,
    measurement_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BenchmarkComparisonKey {
    scope: BenchmarkMeasurementScope,
    lineage: BenchmarkComparisonLineage,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BenchmarkClaimProofKey {
    workload_class: String,
    scenario: String,
    guest_run_lineage: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct BenchmarkClaimProofAvailability {
    ready_scenarios: BTreeSet<String>,
}

impl BenchmarkClaimProofAvailability {
    fn has_steady_state_proof(&self) -> bool {
        self.ready_scenarios.contains("steady_state")
    }

    fn has_boot_path_proof(&self) -> bool {
        self.ready_scenarios.contains("cold_boot")
            || self.ready_scenarios.contains("service_readiness")
    }

    fn has_density_proof(&self) -> bool {
        self.ready_scenarios.contains("clone_fanout")
            || self.ready_scenarios.contains("noisy_neighbor_density")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct GeneratedValidationManifest {
    #[serde(default)]
    bundle: String,
    #[serde(default)]
    artifacts: Vec<GeneratedValidationArtifactManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct GeneratedValidationArtifactManifestEntry {
    path: String,
    kind: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    generated_at: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GeneratedValidationClaimDescriptor {
    claim_tier: String,
    evidence_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GeneratedValidationScenarioRow {
    scenario: String,
    source_engine: String,
    observe_engine: String,
    backend: Option<String>,
    measurement_mode: String,
    boot_time_ms: u32,
    steady_state_score: u32,
    control_plane_p99_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GeneratedValidationReport {
    artifact_path: String,
    artifact_sha256: Option<String>,
    bundle: String,
    generated_at: OffsetDateTime,
    target: String,
    host_platform: String,
    execution_environment: String,
    measurement_mode: String,
    workload_class: String,
    guest_run_lineage: Option<String>,
    host_class_evidence_key: String,
    references: Vec<String>,
    uvm_claim: GeneratedValidationClaimDescriptor,
    qemu_claim: GeneratedValidationClaimDescriptor,
    scenarios: Vec<GeneratedValidationScenarioRow>,
}

const MAX_WORKLOAD_CLASS_LEN: usize = 64;
const MAX_CATEGORY_LEN: usize = 64;
const MAX_SEVERITY_LEN: usize = 32;
const MAX_SUMMARY_LEN: usize = 1024;
const MAX_NOTE_LEN: usize = 1024;
const MAX_SCENARIO_LEN: usize = 64;
const MAX_GUEST_RUN_LINEAGE_LEN: usize = 128;
const REQUIRED_WORKLOAD_CLASSES: &[&str] = &[
    "general",
    "cpu_intensive",
    "io_intensive",
    "network_intensive",
];
const ALLOWED_SEVERITIES: &[&str] = &["info", "warning", "error", "critical"];

fn default_observe_timestamp() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

fn default_claim_tier_key() -> String {
    String::from(ClaimTier::Compatible.as_str())
}

fn default_claim_evidence_mode_key() -> String {
    String::from(ClaimEvidenceMode::Measured.as_str())
}

fn fallback_portability_source(
    portability_assessment: Option<&UvmPortabilityAssessment>,
) -> UvmPortabilityAssessmentSource {
    if portability_assessment.is_some() {
        UvmPortabilityAssessmentSource::RequestFallback
    } else {
        UvmPortabilityAssessmentSource::Unavailable
    }
}

fn runtime_preflight_fallback_portability_source(
    stored_portability_assessment: Option<&UvmPortabilityAssessment>,
    request_assessment: Option<&UvmPortabilityAssessment>,
) -> UvmPortabilityAssessmentSource {
    if stored_portability_assessment.is_some() {
        UvmPortabilityAssessmentSource::RuntimePreflightFallback
    } else {
        fallback_portability_source(request_assessment)
    }
}

fn normalize_claim_tier(value: Option<&str>) -> Result<String> {
    match value {
        Some(value) => ClaimTier::parse(value).map(|value| String::from(value.as_str())),
        None => Ok(default_claim_tier_key()),
    }
}

fn claim_decision_annotation_claim_tier(
    metadata: &ResourceMetadata,
    key: &str,
) -> Result<Option<String>> {
    metadata
        .annotations
        .get(key)
        .map(|value| normalize_claim_tier(Some(value.as_str())))
        .transpose()
}

fn claim_decision_annotation_benchmark_ready_scenarios(metadata: &ResourceMetadata) -> Vec<String> {
    metadata
        .annotations
        .get("benchmark_ready_scenarios")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn resolve_claim_decision_claim_tier(
    current: &str,
    metadata: &ResourceMetadata,
    annotation_key: &str,
    fallback: &str,
) -> Result<String> {
    if let Some(value) = claim_decision_annotation_claim_tier(metadata, annotation_key)? {
        return Ok(value);
    }
    if !current.trim().is_empty() {
        return normalize_claim_tier(Some(current));
    }
    normalize_claim_tier(Some(fallback))
}

fn resolve_claim_decision_benchmark_ready_scenarios(
    current: &[String],
    metadata: &ResourceMetadata,
) -> Vec<String> {
    let annotated = claim_decision_annotation_benchmark_ready_scenarios(metadata);
    if !annotated.is_empty() {
        return annotated;
    }
    current.to_vec()
}

fn normalize_claim_evidence_mode(value: Option<&str>) -> Result<String> {
    match value.map(|value| value.trim().to_ascii_lowercase()) {
        Some(value) => match value.as_str() {
            "measured" => Ok(String::from(ClaimEvidenceMode::Measured.as_str())),
            "simulated" => Ok(String::from(ClaimEvidenceMode::Simulated.as_str())),
            "prohibited" => Ok(String::from(ClaimEvidenceMode::Prohibited.as_str())),
            _ => Err(PlatformError::invalid(
                "claim_evidence_mode must be one of measured/simulated/prohibited",
            )),
        },
        None => Ok(default_claim_evidence_mode_key()),
    }
}

fn parse_claim_evidence_mode(value: &str) -> Result<ClaimEvidenceMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "measured" => Ok(ClaimEvidenceMode::Measured),
        "simulated" => Ok(ClaimEvidenceMode::Simulated),
        "prohibited" => Ok(ClaimEvidenceMode::Prohibited),
        _ => Err(PlatformError::invalid(
            "claim_evidence_mode must be one of measured/simulated/prohibited",
        )),
    }
}

fn claim_tier_rank(value: ClaimTier) -> u8 {
    match value {
        ClaimTier::ResearchOnly => 0,
        ClaimTier::Compatible => 1,
        ClaimTier::Competitive => 2,
        ClaimTier::FasterBootPath => 3,
        ClaimTier::FasterDensity => 4,
        ClaimTier::FasterThanKvmForWorkloadClass => 5,
    }
}

fn strongest_claim_tier(current: Option<ClaimTier>, candidate: ClaimTier) -> ClaimTier {
    match current {
        Some(current) if claim_tier_rank(current) >= claim_tier_rank(candidate) => current,
        _ => candidate,
    }
}

fn strongest_publishable_claim_tier(
    observed: ClaimTier,
    evidence_mode: ClaimEvidenceMode,
    proof: &BenchmarkClaimProofAvailability,
) -> ClaimTier {
    match evidence_mode {
        ClaimEvidenceMode::Prohibited => ClaimTier::ResearchOnly,
        ClaimEvidenceMode::Simulated => match observed {
            ClaimTier::ResearchOnly => ClaimTier::ResearchOnly,
            _ => ClaimTier::Compatible,
        },
        ClaimEvidenceMode::Measured => match observed {
            ClaimTier::ResearchOnly => ClaimTier::ResearchOnly,
            ClaimTier::Compatible => ClaimTier::Compatible,
            ClaimTier::Competitive => {
                if proof.has_steady_state_proof() {
                    ClaimTier::Competitive
                } else {
                    ClaimTier::Compatible
                }
            }
            ClaimTier::FasterBootPath => {
                if proof.has_boot_path_proof() {
                    ClaimTier::FasterBootPath
                } else if proof.has_steady_state_proof() {
                    ClaimTier::Competitive
                } else {
                    ClaimTier::Compatible
                }
            }
            ClaimTier::FasterDensity => {
                if proof.has_density_proof() {
                    ClaimTier::FasterDensity
                } else if proof.has_steady_state_proof() {
                    ClaimTier::Competitive
                } else {
                    ClaimTier::Compatible
                }
            }
            ClaimTier::FasterThanKvmForWorkloadClass => {
                if proof.has_steady_state_proof()
                    && proof.has_boot_path_proof()
                    && proof.has_density_proof()
                {
                    ClaimTier::FasterThanKvmForWorkloadClass
                } else if proof.has_density_proof() {
                    ClaimTier::FasterDensity
                } else if proof.has_boot_path_proof() {
                    ClaimTier::FasterBootPath
                } else if proof.has_steady_state_proof() {
                    ClaimTier::Competitive
                } else {
                    ClaimTier::Compatible
                }
            }
        },
    }
}

fn normalize_host_evidence_mode(value: &str) -> Result<String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "measured" => Ok(String::from(ClaimEvidenceMode::Measured.as_str())),
        "simulated" => Ok(String::from(ClaimEvidenceMode::Simulated.as_str())),
        "prohibited" => Ok(String::from(ClaimEvidenceMode::Prohibited.as_str())),
        _ => Err(PlatformError::invalid(
            "evidence_mode must be one of measured/simulated/prohibited",
        )),
    }
}

fn normalize_claim_status(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "allowed" | "restricted" | "prohibited" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "claim status must be one of allowed/restricted/prohibited",
        )),
    }
}

fn normalize_host_platform(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "linux" | "windows" | "macos" | "freebsd" | "openbsd" | "netbsd" | "dragonflybsd"
        | "illumos" | "other" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "host_platform must be one of linux/windows/macos/freebsd/openbsd/netbsd/dragonflybsd/illumos/other",
        )),
    }
}

fn normalize_execution_environment(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "bare_metal" | "container_restricted" | "hosted_ci" | "operator_declared" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "execution_environment must be one of bare_metal/container_restricted/hosted_ci/operator_declared",
        )),
    }
}

fn derive_observe_host_class(host_platform: &str, execution_environment: &str) -> String {
    let host_platform = HostPlatform::parse(host_platform).unwrap_or(HostPlatform::Other);
    let environment = HostClassEnvironment::parse(execution_environment)
        .unwrap_or(HostClassEnvironment::OperatorDeclared);
    HostClass::from_platform_environment(host_platform, environment).into_string()
}

fn canonical_host_class_evidence_key(host_class: &str) -> Result<String> {
    HostClass::parse(host_class).map(HostClass::into_string)
}

fn extract_node_capability_evidence_value(summary: &str, key: &str) -> Option<String> {
    summary.split_whitespace().find_map(|token| {
        let (candidate_key, candidate_value) = token.split_once('=')?;
        if candidate_key == key {
            Some(candidate_value.trim_matches(',').to_owned())
        } else {
            None
        }
    })
}

fn portability_evidence_value<'a>(summary: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    summary
        .split_whitespace()
        .find_map(|token| token.strip_prefix(prefix.as_str()))
}

fn host_platform_from_host_class(host_class: &str) -> Option<String> {
    let (candidate, _) = host_class.split_once('_')?;
    normalize_host_platform(candidate).ok()
}

fn scoped_image_publication_scope(
    portability_assessment: Option<&UvmPortabilityAssessment>,
) -> Result<Option<ScopedImagePublicationScope>> {
    let Some(portability_assessment) = portability_assessment else {
        return Ok(None);
    };
    let Some(row) = portability_assessment.evidence.iter().find(|row| {
        row.source == UvmCompatibilityEvidenceSource::ImageContract
            && row
                .summary
                .starts_with("scoped image compatibility artifact ")
    }) else {
        return Ok(None);
    };
    let host_class = portability_evidence_value(&row.summary, "host_class").ok_or_else(|| {
        PlatformError::invalid("scoped image compatibility artifact is missing `host_class`")
    })?;
    let claim_tier = portability_evidence_value(&row.summary, "claim_tier").ok_or_else(|| {
        PlatformError::invalid("scoped image compatibility artifact is missing `claim_tier`")
    })?;
    let machine_family =
        portability_evidence_value(&row.summary, "machine_family").ok_or_else(|| {
            PlatformError::invalid(
                "scoped image compatibility artifact is missing `machine_family`",
            )
        })?;
    let guest_profile =
        portability_evidence_value(&row.summary, "guest_profile").ok_or_else(|| {
            PlatformError::invalid("scoped image compatibility artifact is missing `guest_profile`")
        })?;
    Ok(Some(ScopedImagePublicationScope {
        host_class: host_class.to_owned(),
        host_class_evidence_key: canonical_host_class_evidence_key(host_class)?,
        region: portability_evidence_value(&row.summary, "region").map(str::to_owned),
        cell: portability_evidence_value(&row.summary, "cell").map(str::to_owned),
        claim_tier: claim_tier.to_owned(),
        selected_backend: portability_evidence_value(&row.summary, "accelerator_backend")
            .map(str::to_owned),
        machine_family: machine_family.to_owned(),
        guest_profile: guest_profile.to_owned(),
    }))
}

fn resolve_publication_scope(
    portability_assessment: Option<&UvmPortabilityAssessment>,
    linked_preflight_artifact: Option<&UvmPreflightEvidenceArtifact>,
    host_evidence: Option<&UvmHostEvidenceRecord>,
) -> Result<ResolvedPublicationScope> {
    if let Some(scope) = scoped_image_publication_scope(portability_assessment)? {
        return Ok(ResolvedPublicationScope::from_scoped_image(scope));
    }
    if let Some(linked_preflight_artifact) = linked_preflight_artifact {
        if let Some(scope) = scoped_image_publication_scope(
            linked_preflight_artifact.portability_assessment.as_ref(),
        )? {
            return Ok(ResolvedPublicationScope::from_scoped_image(scope));
        }
        return Ok(ResolvedPublicationScope {
            host_class_evidence_key: Some(
                linked_preflight_artifact.host_class_evidence_key.clone(),
            ),
            ..ResolvedPublicationScope::default()
        });
    }
    Ok(ResolvedPublicationScope {
        host_class_evidence_key: host_evidence
            .map(|evidence| evidence.host_class_evidence_key.clone()),
        ..ResolvedPublicationScope::default()
    })
}

fn preflight_host_axes(
    preflight: &NodeRuntimePreflightPortabilityRecord,
) -> Result<Option<(String, String, Option<String>)>> {
    let Some(assessment) = preflight.compatibility_assessment.as_ref() else {
        return Ok(None);
    };
    let Some(row) = assessment
        .evidence
        .iter()
        .find(|row| row.source == UvmCompatibilityEvidenceSource::NodeCapability)
    else {
        return Ok(None);
    };
    let Some(host_platform) = extract_node_capability_evidence_value(&row.summary, "host_platform")
    else {
        return Ok(None);
    };
    let Some(host_class) = extract_node_capability_evidence_value(&row.summary, "host_class")
    else {
        return Ok(None);
    };
    Ok(Some((
        normalize_host_platform(&host_platform)?,
        canonical_host_class_evidence_key(&host_class)?,
        row.evidence_mode.clone(),
    )))
}

fn normalize_optional_note(value: Option<String>) -> Result<Option<String>> {
    value
        .map(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(PlatformError::invalid(
                    "note may not be empty when provided",
                ));
            }
            if trimmed.len() > MAX_NOTE_LEN {
                return Err(PlatformError::invalid("note exceeds 1024 bytes"));
            }
            if trimmed.chars().any(|character| character.is_control()) {
                return Err(PlatformError::invalid(
                    "note may not contain control characters",
                ));
            }
            Ok(trimmed.to_owned())
        })
        .transpose()
}

fn normalize_benchmark_target(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "host" | "ubuntu_22_04_vm" | "apple_mac_studio_m1_pro_sim" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "target must be one of host/ubuntu_22_04_vm/apple_mac_studio_m1_pro_sim",
        )),
    }
}

fn normalize_benchmark_engine(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "software_dbt" | "qemu" | "container" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "engine must be one of software_dbt/qemu/container",
        )),
    }
}

fn normalize_benchmark_scenario(value: &str) -> Result<String> {
    let normalized = normalize_token(value, "scenario", MAX_SCENARIO_LEN)?;
    match normalized.as_str() {
        "cold_boot"
        | "steady_state"
        | "migration_pressure"
        | "service_readiness"
        | "clone_fanout"
        | "snapshot_resume"
        | "block_io_mixed"
        | "userspace_network"
        | "noisy_neighbor_density"
        | "fault_recovery" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "scenario must be one of cold_boot/steady_state/migration_pressure/service_readiness/clone_fanout/snapshot_resume/block_io_mixed/userspace_network/noisy_neighbor_density/fault_recovery",
        )),
    }
}

fn normalize_optional_benchmark_scenario(value: Option<String>, measured: bool) -> Result<String> {
    match value {
        Some(value) => normalize_benchmark_scenario(&value),
        None if measured => Err(PlatformError::invalid(
            "measured benchmark baselines require scenario",
        )),
        None => Ok(String::new()),
    }
}

fn benchmark_target_requires_guest_run_lineage(target: &str) -> bool {
    target != "host"
}

fn normalize_benchmark_measurement_mode(
    value: Option<String>,
    measured: bool,
) -> Result<Option<String>> {
    match value {
        Some(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            let mode = match normalized.as_str() {
                "direct" => MeasurementMode::Direct,
                "hybrid" => MeasurementMode::Hybrid,
                "modeled" => MeasurementMode::Modeled,
                _ => {
                    return Err(PlatformError::invalid(
                        "measurement_mode must be one of direct/hybrid/modeled",
                    ));
                }
            };
            Ok(Some(String::from(mode.as_str())))
        }
        None if measured => Err(PlatformError::invalid(
            "measured benchmark rows require measurement_mode",
        )),
        None => Ok(None),
    }
}

fn normalize_benchmark_guest_run_lineage(
    value: Option<String>,
    target: &str,
    measured: bool,
) -> Result<Option<String>> {
    let requires_guest_run_lineage =
        measured && benchmark_target_requires_guest_run_lineage(target);
    match value {
        Some(value) => {
            if !benchmark_target_requires_guest_run_lineage(target) {
                return Err(PlatformError::invalid(
                    "host benchmark rows may not include guest_run_lineage",
                ));
            }
            normalize_token(&value, "guest_run_lineage", MAX_GUEST_RUN_LINEAGE_LEN).map(Some)
        }
        None if requires_guest_run_lineage => Err(PlatformError::invalid(
            "measured guest benchmark rows require guest_run_lineage",
        )),
        None => Ok(None),
    }
}

fn benchmark_measurement_storage_key(scope: &BenchmarkMeasurementScope) -> String {
    format!(
        "measured:{}:{}:{}:{}",
        scope.host_class_evidence_key, scope.workload_class, scope.scenario, scope.engine
    )
}

fn benchmark_measurement_scope_descriptor(scope: &BenchmarkMeasurementScope) -> String {
    format!(
        "host_class={} workload_class={} scenario={} engine={}",
        scope.host_class_evidence_key, scope.workload_class, scope.scenario, scope.engine
    )
}

fn benchmark_comparison_lineage_descriptor(lineage: &BenchmarkComparisonLineage) -> String {
    format!(
        "guest_run_lineage={} measurement_mode={}",
        lineage.guest_run_lineage.as_deref().unwrap_or("host_scope"),
        lineage.measurement_mode
    )
}

fn benchmark_comparison_key_descriptor(key: &BenchmarkComparisonKey) -> String {
    format!(
        "{} {}",
        benchmark_measurement_scope_descriptor(&key.scope),
        benchmark_comparison_lineage_descriptor(&key.lineage)
    )
}

fn measured_benchmark_scope(
    host_class_evidence_key: Option<&str>,
    workload_class: &str,
    scenario: &str,
    engine: &str,
    measured: bool,
) -> Option<BenchmarkMeasurementScope> {
    if !measured || workload_class.is_empty() || scenario.is_empty() {
        return None;
    }
    let host_class_evidence_key = host_class_evidence_key?;
    Some(BenchmarkMeasurementScope {
        host_class_evidence_key: host_class_evidence_key.to_owned(),
        workload_class: workload_class.to_owned(),
        scenario: scenario.to_owned(),
        engine: engine.to_owned(),
    })
}

fn measured_benchmark_comparison_lineage(
    guest_run_lineage: Option<&str>,
    measurement_mode: Option<&str>,
    measured: bool,
) -> Option<BenchmarkComparisonLineage> {
    if !measured {
        return None;
    }
    Some(BenchmarkComparisonLineage {
        guest_run_lineage: guest_run_lineage.map(str::to_owned),
        measurement_mode: measurement_mode?.to_owned(),
    })
}

fn normalize_token(value: &str, field: &'static str, max_len: usize) -> Result<String> {
    let trimmed = value.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty")));
    }
    if trimmed.len() > max_len {
        return Err(PlatformError::invalid(format!(
            "{field} exceeds {max_len} bytes"
        )));
    }
    if !trimmed.chars().all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '-' | '_')
    }) {
        return Err(PlatformError::invalid(format!(
            "{field} may only contain lowercase ascii letters, digits, dashes, and underscores"
        )));
    }
    Ok(trimmed)
}

fn normalize_severity(value: &str) -> Result<String> {
    let normalized = normalize_token(value, "severity", MAX_SEVERITY_LEN)?;
    if !ALLOWED_SEVERITIES.contains(&normalized.as_str()) {
        return Err(PlatformError::invalid(
            "severity must be one of info, warning, error, critical",
        ));
    }
    Ok(normalized)
}

fn normalize_summary(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid("summary may not be empty"));
    }
    if trimmed.len() > MAX_SUMMARY_LEN {
        return Err(PlatformError::invalid("summary exceeds 1024 bytes"));
    }
    if trimmed.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "summary may not contain control characters",
        ));
    }
    Ok(trimmed.to_owned())
}

fn validate_percentage(field: &'static str, value: u16) -> Result<u16> {
    if value > 100 {
        return Err(PlatformError::invalid(format!(
            "{field} must be between 0 and 100"
        )));
    }
    Ok(value)
}

fn perf_request_fingerprint(
    instance_id: &UvmInstanceId,
    workload_class: &str,
    cpu_overhead_pct: u16,
    memory_overhead_pct: u16,
    block_io_latency_overhead_pct: u16,
    network_latency_overhead_pct: u16,
    jitter_pct: u16,
) -> String {
    sha256_hex(
        format!(
            "uvm-perf:v1|{}|{}|{}|{}|{}|{}|{}",
            instance_id.as_str(),
            workload_class,
            cpu_overhead_pct,
            memory_overhead_pct,
            block_io_latency_overhead_pct,
            network_latency_overhead_pct,
            jitter_pct
        )
        .as_bytes(),
    )
}

fn failure_report_fingerprint(
    instance_id: Option<&UvmInstanceId>,
    category: &str,
    severity: &str,
    summary: &str,
    recovered: bool,
    forensic_capture_requested: bool,
) -> String {
    sha256_hex(
        format!(
            "uvm-failure:v1|{}|{}|{}|{}|{}|{}",
            instance_id.map(UvmInstanceId::as_str).unwrap_or("-"),
            category,
            severity,
            summary,
            recovered,
            forensic_capture_requested
        )
        .as_bytes(),
    )
}

fn find_generated_validation_manifest_path(state_root: &Path) -> Option<PathBuf> {
    state_root.ancestors().find_map(|candidate_root| {
        let candidate =
            candidate_root.join("docs/benchmarks/generated/uvm-stack-validation-manifest.json");
        candidate.is_file().then_some(candidate)
    })
}

fn generated_validation_workspace_root(manifest_path: &Path) -> Result<PathBuf> {
    manifest_path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            PlatformError::invalid("generated validation manifest path is missing workspace root")
                .with_detail(manifest_path.display().to_string())
        })
}

fn parse_generated_validation_manifest(
    manifest_path: &Path,
) -> Result<GeneratedValidationManifest> {
    let raw = fs::read_to_string(manifest_path).map_err(|error| {
        PlatformError::unavailable("failed to read generated validation manifest")
            .with_detail(format!("{}: {error}", manifest_path.display()))
    })?;
    serde_json::from_str(&raw).map_err(|error| {
        PlatformError::invalid("generated validation manifest is invalid")
            .with_detail(format!("{}: {error}", manifest_path.display()))
    })
}

fn generated_validation_extract_markdown_field(
    contents: &str,
    prefix: &str,
    context: &str,
) -> Result<String> {
    contents
        .lines()
        .find_map(|line| line.strip_prefix(prefix).map(str::trim))
        .map(str::to_owned)
        .ok_or_else(|| {
            PlatformError::invalid("generated validation report is missing a required field")
                .with_detail(format!("{context}: missing `{prefix}`"))
        })
}

fn generated_validation_parse_markdown_claim(
    raw: &str,
    label: &str,
    context: &str,
) -> Result<GeneratedValidationClaimDescriptor> {
    let (claim_tier_raw, evidence_mode_raw) = raw.rsplit_once('(').ok_or_else(|| {
        PlatformError::invalid("generated validation report claim line is malformed")
            .with_detail(format!("{context}: `{label}` missing evidence mode"))
    })?;
    let claim_tier = claim_tier_raw.trim().trim_matches('`').trim().to_owned();
    let evidence_mode = evidence_mode_raw
        .trim()
        .trim_end_matches(')')
        .trim()
        .to_owned();
    if claim_tier.is_empty() {
        return Err(PlatformError::invalid(
            "generated validation report claim tier may not be empty",
        )
        .with_detail(format!("{context}: `{label}`")));
    }
    let evidence_mode = normalize_host_evidence_mode(&evidence_mode)?;
    Ok(GeneratedValidationClaimDescriptor {
        claim_tier,
        evidence_mode,
    })
}

fn generated_validation_parse_metric_u32(raw: &str, field: &str, context: &str) -> Result<u32> {
    let value = raw.parse::<f64>().map_err(|error| {
        PlatformError::invalid("generated validation metric is invalid")
            .with_detail(format!("{context}: invalid `{field}` `{raw}`: {error}"))
    })?;
    if !value.is_finite() || value < 0.0 || value > f64::from(u32::MAX) {
        return Err(
            PlatformError::invalid("generated validation metric is out of range")
                .with_detail(format!("{context}: invalid `{field}` `{raw}`")),
        );
    }
    Ok(value.round() as u32)
}

fn generated_validation_extract_note_value(notes: &str, key: &str) -> Option<String> {
    notes.split(';').find_map(|entry| {
        let (entry_key, entry_value) = entry.trim().split_once('=')?;
        (entry_key.trim() == key).then(|| entry_value.trim().to_owned())
    })
}

fn generated_validation_observe_engine(
    source_engine: &str,
    backend: Option<&str>,
) -> Result<String> {
    match source_engine.trim() {
        "qemu" => Ok(String::from("qemu")),
        "uvm" => {
            if backend
                .map(|value| value.contains("container"))
                .unwrap_or(false)
            {
                Ok(String::from("container"))
            } else {
                // Validation reports can describe intended backends such as
                // `apple_virtualization`, but the current observe benchmark
                // families still normalize UVM-side rows into the
                // `software_dbt` engine key and carry the declared backend in
                // row notes and metadata annotations.
                Ok(String::from("software_dbt"))
            }
        }
        other => Err(
            PlatformError::invalid("generated validation scenario engine is unsupported")
                .with_detail(format!("unsupported engine `{other}`")),
        ),
    }
}

fn generated_validation_extract_section<'a>(
    contents: &'a str,
    start_header: &str,
    end_header: &str,
    context: &str,
) -> Result<Vec<&'a str>> {
    let start = contents.find(start_header).ok_or_else(|| {
        PlatformError::invalid("generated validation report is missing a required section")
            .with_detail(format!("{context}: missing `{start_header}`"))
    })?;
    let section = &contents[start + start_header.len()..];
    let end = section.find(end_header).ok_or_else(|| {
        PlatformError::invalid("generated validation report is missing a required section")
            .with_detail(format!("{context}: missing `{end_header}`"))
    })?;
    Ok(section[..end].lines().collect())
}

fn generated_validation_parse_scenarios(
    contents: &str,
    context: &str,
) -> Result<Vec<GeneratedValidationScenarioRow>> {
    let lines = generated_validation_extract_section(
        contents,
        "## Scenario matrix",
        "## Stress phases",
        context,
    )?;
    let mut rows = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            continue;
        }
        if trimmed.contains("---") || trimmed.contains("Scenario | Engine") {
            continue;
        }
        let cells = trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect::<Vec<_>>();
        if cells.len() != 7 {
            return Err(
                PlatformError::invalid("generated validation scenario row is malformed")
                    .with_detail(format!("{context}: `{trimmed}`")),
            );
        }
        let backend = generated_validation_extract_note_value(cells[6], "backend");
        let observe_engine = generated_validation_observe_engine(cells[1], backend.as_deref())?;
        let measurement_mode =
            normalize_benchmark_measurement_mode(Some(cells[2].to_owned()), true)?
                .unwrap_or_else(|| String::from(MeasurementMode::Modeled.as_str()));
        rows.push(GeneratedValidationScenarioRow {
            scenario: normalize_benchmark_scenario(cells[0])?,
            source_engine: cells[1].to_owned(),
            observe_engine,
            backend,
            measurement_mode,
            boot_time_ms: generated_validation_parse_metric_u32(cells[3], "boot_time_ms", context)?,
            steady_state_score: generated_validation_parse_metric_u32(
                cells[4],
                "steady_state_score",
                context,
            )?,
            control_plane_p99_ms: generated_validation_parse_metric_u32(
                cells[5],
                "control_plane_p99_ms",
                context,
            )?,
        });
    }
    if rows.is_empty() {
        return Err(
            PlatformError::invalid("generated validation report scenario matrix is empty")
                .with_detail(context.to_owned()),
        );
    }
    Ok(rows)
}

fn generated_validation_parse_month(month: u8, raw: &str, context: &str) -> Result<Month> {
    match month {
        1 => Ok(Month::January),
        2 => Ok(Month::February),
        3 => Ok(Month::March),
        4 => Ok(Month::April),
        5 => Ok(Month::May),
        6 => Ok(Month::June),
        7 => Ok(Month::July),
        8 => Ok(Month::August),
        9 => Ok(Month::September),
        10 => Ok(Month::October),
        11 => Ok(Month::November),
        12 => Ok(Month::December),
        _ => Err(
            PlatformError::invalid("generated validation timestamp month is invalid")
                .with_detail(format!("{context}: `{raw}`")),
        ),
    }
}

fn generated_validation_parse_i32(
    raw: &str,
    field: &str,
    source: &str,
    context: &str,
) -> Result<i32> {
    raw.parse::<i32>().map_err(|error| {
        PlatformError::invalid("generated validation timestamp is invalid").with_detail(format!(
            "{context}: invalid {field} `{raw}` in `{source}`: {error}"
        ))
    })
}

fn generated_validation_parse_u8(
    raw: &str,
    field: &str,
    source: &str,
    context: &str,
) -> Result<u8> {
    raw.parse::<u8>().map_err(|error| {
        PlatformError::invalid("generated validation timestamp is invalid").with_detail(format!(
            "{context}: invalid {field} `{raw}` in `{source}`: {error}"
        ))
    })
}

fn generated_validation_parse_i8(
    raw: &str,
    field: &str,
    source: &str,
    context: &str,
) -> Result<i8> {
    raw.parse::<i8>().map_err(|error| {
        PlatformError::invalid("generated validation timestamp is invalid").with_detail(format!(
            "{context}: invalid {field} `{raw}` in `{source}`: {error}"
        ))
    })
}

fn generated_validation_parse_date(raw: &str, context: &str) -> Result<Date> {
    let mut parts = raw.split('-');
    let year = generated_validation_parse_i32(parts.next().unwrap_or(""), "year", raw, context)?;
    let month = generated_validation_parse_u8(parts.next().unwrap_or(""), "month", raw, context)?;
    let day = generated_validation_parse_u8(parts.next().unwrap_or(""), "day", raw, context)?;
    if parts.next().is_some() {
        return Err(
            PlatformError::invalid("generated validation timestamp date is invalid")
                .with_detail(format!("{context}: `{raw}`")),
        );
    }
    Date::from_calendar_date(
        year,
        generated_validation_parse_month(month, raw, context)?,
        day,
    )
    .map_err(|error| {
        PlatformError::invalid("generated validation timestamp date is invalid")
            .with_detail(format!("{context}: `{raw}`: {error}"))
    })
}

fn generated_validation_parse_time(raw: &str, context: &str) -> Result<Time> {
    let mut parts = raw.split('.');
    let clock = parts.next().unwrap_or("");
    let fractional = parts.next().unwrap_or("0");
    if parts.next().is_some() {
        return Err(
            PlatformError::invalid("generated validation timestamp time is invalid")
                .with_detail(format!("{context}: `{raw}`")),
        );
    }
    let mut clock_parts = clock.split(':');
    let hour =
        generated_validation_parse_u8(clock_parts.next().unwrap_or(""), "hour", raw, context)?;
    let minute =
        generated_validation_parse_u8(clock_parts.next().unwrap_or(""), "minute", raw, context)?;
    let second =
        generated_validation_parse_u8(clock_parts.next().unwrap_or(""), "second", raw, context)?;
    if clock_parts.next().is_some() {
        return Err(
            PlatformError::invalid("generated validation timestamp time is invalid")
                .with_detail(format!("{context}: `{raw}`")),
        );
    }
    let mut nanos_text = fractional.to_owned();
    if nanos_text.len() > 9 {
        nanos_text.truncate(9);
    }
    while nanos_text.len() < 9 {
        nanos_text.push('0');
    }
    let nanos = nanos_text.parse::<u32>().map_err(|error| {
        PlatformError::invalid("generated validation timestamp fractional seconds are invalid")
            .with_detail(format!("{context}: `{raw}`: {error}"))
    })?;
    Time::from_hms_nano(hour, minute, second, nanos).map_err(|error| {
        PlatformError::invalid("generated validation timestamp time is invalid")
            .with_detail(format!("{context}: `{raw}`: {error}"))
    })
}

fn generated_validation_parse_offset(raw: &str, context: &str) -> Result<UtcOffset> {
    let sign = match raw.chars().next() {
        Some('+') => 1,
        Some('-') => -1,
        Some(other) => {
            return Err(
                PlatformError::invalid("generated validation timestamp offset is invalid")
                    .with_detail(format!("{context}: invalid sign `{other}` in `{raw}`")),
            );
        }
        None => {
            return Err(
                PlatformError::invalid("generated validation timestamp offset is invalid")
                    .with_detail(format!("{context}: `{raw}`")),
            );
        }
    };
    let mut parts = raw[1..].split(':');
    let hours =
        generated_validation_parse_i8(parts.next().unwrap_or(""), "offset hour", raw, context)?;
    let minutes =
        generated_validation_parse_i8(parts.next().unwrap_or(""), "offset minute", raw, context)?;
    let seconds =
        generated_validation_parse_i8(parts.next().unwrap_or(""), "offset second", raw, context)?;
    if parts.next().is_some() {
        return Err(
            PlatformError::invalid("generated validation timestamp offset is invalid")
                .with_detail(format!("{context}: `{raw}`")),
        );
    }
    UtcOffset::from_hms(sign * hours, sign * minutes, sign * seconds).map_err(|error| {
        PlatformError::invalid("generated validation timestamp offset is invalid")
            .with_detail(format!("{context}: `{raw}`: {error}"))
    })
}

fn parse_generated_validation_timestamp(raw: &str, context: &str) -> Result<OffsetDateTime> {
    let mut parts = raw.split_whitespace();
    let date = parts.next().unwrap_or("");
    let time = parts.next().unwrap_or("");
    let offset = parts.next().unwrap_or("");
    if parts.next().is_some() {
        return Err(
            PlatformError::invalid("generated validation timestamp is invalid")
                .with_detail(format!("{context}: `{raw}`")),
        );
    }
    Ok(PrimitiveDateTime::new(
        generated_validation_parse_date(date, context)?,
        generated_validation_parse_time(time, context)?,
    )
    .assume_offset(generated_validation_parse_offset(offset, context)?))
}

fn generated_validation_safe_token(
    raw: &str,
    field: &'static str,
    max_len: usize,
) -> Result<String> {
    let mut normalized = String::new();
    let mut previous_separator = false;
    for character in raw.trim().chars() {
        let mapped = if character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '-' | '_')
        {
            character
        } else if character.is_ascii_uppercase() {
            character.to_ascii_lowercase()
        } else {
            '_'
        };
        if mapped == '_' {
            if !previous_separator {
                normalized.push(mapped);
                previous_separator = true;
            }
        } else {
            normalized.push(mapped);
            previous_separator = false;
        }
    }
    normalize_token(normalized.trim_matches('_'), field, max_len)
}

fn generated_validation_workload_class(target: &str) -> Result<String> {
    generated_validation_safe_token(
        &format!("generated_validation_{target}"),
        "workload_class",
        MAX_WORKLOAD_CLASS_LEN,
    )
}

fn generated_validation_guest_run_lineage(bundle: &str, target: &str) -> Result<Option<String>> {
    if !benchmark_target_requires_guest_run_lineage(target) {
        return Ok(None);
    }
    generated_validation_safe_token(
        &format!("{bundle}_{target}"),
        "guest_run_lineage",
        MAX_GUEST_RUN_LINEAGE_LEN,
    )
    .map(Some)
}

fn generated_validation_report_from_manifest_entry(
    workspace_root: &Path,
    manifest: &GeneratedValidationManifest,
    entry: &GeneratedValidationArtifactManifestEntry,
) -> Result<GeneratedValidationReport> {
    let report_path = if Path::new(&entry.path).is_absolute() {
        PathBuf::from(&entry.path)
    } else {
        workspace_root.join(&entry.path)
    };
    let raw = fs::read_to_string(&report_path).map_err(|error| {
        PlatformError::unavailable("failed to read generated validation report")
            .with_detail(format!("{}: {error}", report_path.display()))
    })?;
    let context = report_path.display().to_string();
    let generated_at = parse_generated_validation_timestamp(
        &generated_validation_extract_markdown_field(&raw, "- Generated at:", &context)?,
        &context,
    )?;
    let target = normalize_benchmark_target(
        generated_validation_extract_markdown_field(&raw, "- Target:", &context)?.trim_matches('`'),
    )?;
    if let Some(manifest_target) = entry.target.as_deref()
        && manifest_target != target
    {
        return Err(PlatformError::invalid(
            "generated validation report target does not match manifest",
        )
        .with_detail(format!(
            "{}: manifest target `{manifest_target}` does not match report target `{target}`",
            report_path.display()
        )));
    }
    let host_platform = normalize_host_platform(
        generated_validation_extract_markdown_field(&raw, "- Host platform:", &context)?
            .trim_matches('`'),
    )?;
    let execution_environment = normalize_execution_environment(
        generated_validation_extract_markdown_field(&raw, "- Execution environment:", &context)?
            .trim_matches('`'),
    )?;
    let measurement_mode = normalize_benchmark_measurement_mode(
        Some(
            generated_validation_extract_markdown_field(&raw, "- Measurement mode:", &context)?
                .trim_matches('`')
                .to_owned(),
        ),
        true,
    )?
    .unwrap_or_else(|| String::from(MeasurementMode::Modeled.as_str()));
    let workload_class = generated_validation_workload_class(&target)?;
    let guest_run_lineage = generated_validation_guest_run_lineage(&manifest.bundle, &target)?;
    let host_class = derive_observe_host_class(&host_platform, &execution_environment);
    let host_class_evidence_key = canonical_host_class_evidence_key(&host_class)?;
    let uvm_claim = generated_validation_parse_markdown_claim(
        &generated_validation_extract_markdown_field(&raw, "- UVM claim tier:", &context)?,
        "- UVM claim tier:",
        &context,
    )?;
    let qemu_claim = generated_validation_parse_markdown_claim(
        &generated_validation_extract_markdown_field(&raw, "- QEMU claim tier:", &context)?,
        "- QEMU claim tier:",
        &context,
    )?;
    let mut scenarios = generated_validation_parse_scenarios(&raw, &context)?;
    for scenario in &mut scenarios {
        if scenario.measurement_mode != measurement_mode {
            scenario.measurement_mode = measurement_mode.clone();
        }
    }
    Ok(GeneratedValidationReport {
        artifact_path: entry.path.clone(),
        artifact_sha256: entry.sha256.clone(),
        bundle: manifest.bundle.clone(),
        generated_at,
        target,
        host_platform,
        execution_environment,
        measurement_mode,
        workload_class,
        guest_run_lineage,
        host_class_evidence_key,
        references: entry.references.clone(),
        uvm_claim,
        qemu_claim,
        scenarios,
    })
}

fn generated_validation_campaign_storage_key(target: &str) -> String {
    format!("generated_validation_campaign:{target}")
}

fn generated_validation_campaign_name(target: &str) -> String {
    format!("generated-validation-{target}")
}

fn generated_validation_campaign_annotations(
    report: &GeneratedValidationReport,
) -> BTreeMap<String, String> {
    let mut annotations = BTreeMap::new();
    annotations.insert(
        String::from("generated_validation_bundle"),
        report.bundle.clone(),
    );
    annotations.insert(
        String::from("generated_validation_target"),
        report.target.clone(),
    );
    annotations.insert(
        String::from("generated_validation_artifact"),
        report.artifact_path.clone(),
    );
    annotations.insert(
        String::from("generated_validation_host_platform"),
        report.host_platform.clone(),
    );
    annotations.insert(
        String::from("generated_validation_execution_environment"),
        report.execution_environment.clone(),
    );
    annotations.insert(
        String::from("generated_validation_host_class_evidence_key"),
        report.host_class_evidence_key.clone(),
    );
    annotations.insert(
        String::from("generated_validation_measurement_mode"),
        report.measurement_mode.clone(),
    );
    annotations.insert(
        String::from("generated_validation_reference_count"),
        report.references.len().to_string(),
    );
    if let Some(artifact_sha256) = report.artifact_sha256.as_ref() {
        annotations.insert(
            String::from("generated_validation_artifact_sha256"),
            artifact_sha256.clone(),
        );
    }
    annotations
}

fn generated_validation_row_annotations(
    report: &GeneratedValidationReport,
    scenario: &GeneratedValidationScenarioRow,
    claim: &GeneratedValidationClaimDescriptor,
) -> BTreeMap<String, String> {
    let mut annotations = generated_validation_campaign_annotations(report);
    annotations.insert(
        String::from("generated_validation_source_engine"),
        scenario.source_engine.clone(),
    );
    annotations.insert(
        String::from("generated_validation_claim_tier"),
        claim.claim_tier.clone(),
    );
    if let Some(backend) = scenario.backend.as_ref() {
        annotations.insert(
            String::from("generated_validation_backend"),
            backend.clone(),
        );
    }
    annotations
}

fn generated_validation_row_note(
    report: &GeneratedValidationReport,
    scenario: &GeneratedValidationScenarioRow,
    claim: &GeneratedValidationClaimDescriptor,
) -> Result<Option<String>> {
    normalize_optional_note(Some(format!(
        "auto-ingested from {} (source_engine={}, backend={}, claim_tier={}, references={})",
        report.artifact_path,
        scenario.source_engine,
        scenario.backend.as_deref().unwrap_or("unspecified"),
        claim.claim_tier,
        report.references.len()
    )))
}

fn generated_validation_metadata(
    id: &str,
    existing: Option<&ResourceMetadata>,
    updated_at: OffsetDateTime,
    etag_basis: &str,
    annotations: BTreeMap<String, String>,
) -> ResourceMetadata {
    let mut metadata = existing.cloned().unwrap_or_else(|| {
        ResourceMetadata::new(
            OwnershipScope::Platform,
            Some(id.to_owned()),
            sha256_hex(etag_basis.as_bytes()),
        )
    });
    metadata.ownership_scope = OwnershipScope::Platform;
    metadata.owner_id = Some(id.to_owned());
    if existing.is_none() {
        metadata.created_at = updated_at;
        metadata.updated_at = updated_at;
    } else {
        if metadata.updated_at < updated_at {
            metadata.updated_at = updated_at;
        }
        if metadata.created_at > metadata.updated_at {
            metadata.created_at = metadata.updated_at;
        }
    }
    metadata.lifecycle = ResourceLifecycleState::Ready;
    metadata.deleted_at = None;
    metadata.etag = sha256_hex(etag_basis.as_bytes());
    metadata
        .annotations
        .retain(|key, _| !key.starts_with("generated_validation_"));
    metadata.annotations.extend(annotations);
    metadata
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimStatusEvaluation {
    native_indistinguishable_status: bool,
    perf_samples: usize,
    distinct_workload_classes: usize,
    missing_required_workload_classes: Vec<String>,
    failing_workload_classes: Vec<String>,
    observed_highest_claim_tier: String,
    highest_claim_tier: String,
    benchmark_claim_tier_ceiling: String,
    benchmark_ready_scenarios: Vec<String>,
    prohibited_claim_count: u32,
    critical_unrecovered_failures: bool,
    unrecovered_critical_count: usize,
    max_cpu: Option<u16>,
    max_memory: Option<u16>,
    max_block: Option<u16>,
    max_network: Option<u16>,
    max_jitter: Option<u16>,
    claim_status: String,
}

impl ClaimStatusEvaluation {
    fn apply_portability_assessment(
        &mut self,
        portability_assessment: Option<&UvmPortabilityAssessment>,
    ) {
        self.apply_portability_assessments(portability_assessment);
    }

    fn apply_portability_assessments<'a>(
        &mut self,
        portability_assessments: impl IntoIterator<Item = &'a UvmPortabilityAssessment>,
    ) {
        if portability_assessments
            .into_iter()
            .any(|assessment| !assessment.supported)
            && self.claim_status == "allowed"
        {
            self.claim_status = String::from("restricted");
        }
    }
}

/// UVM observe service.
#[derive(Debug, Clone)]
pub struct UvmObserveService {
    perf_attestations: DocumentStore<UvmPerfAttestationRecord>,
    failure_reports: DocumentStore<UvmFailureReportRecord>,
    host_evidence: DocumentStore<UvmHostEvidenceRecord>,
    claim_decisions: DocumentStore<UvmClaimDecisionRecord>,
    runtime_sessions: DocumentStore<NodeRuntimeSessionPresenceRecord>,
    runtime_session_intents: DocumentStore<NodeRuntimeSessionIntentLineageRecord>,
    runtime_preflights: DocumentStore<NodeRuntimePreflightPortabilityRecord>,
    benchmark_campaigns: DocumentStore<UvmBenchmarkCampaignRecord>,
    benchmark_baselines: DocumentStore<UvmBenchmarkBaselineRecord>,
    benchmark_results: DocumentStore<UvmBenchmarkResultRecord>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    state_root: PathBuf,
}

impl UvmObserveService {
    /// Open UVM observe state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let state_root = state_root.as_ref();
        let root = state_root.join("uvm-observe");
        let service = Self {
            perf_attestations: DocumentStore::open(root.join("perf_attestations.json")).await?,
            failure_reports: DocumentStore::open(root.join("failure_reports.json")).await?,
            host_evidence: DocumentStore::open(root.join("host_evidence.json")).await?,
            claim_decisions: DocumentStore::open(root.join("claim_decisions.json")).await?,
            runtime_sessions: DocumentStore::open(
                state_root.join("uvm-node/runtime_sessions.json"),
            )
            .await?,
            runtime_session_intents: DocumentStore::open(
                state_root.join("uvm-node/runtime_session_intents.json"),
            )
            .await?,
            runtime_preflights: DocumentStore::open(
                state_root.join("uvm-node/runtime_preflights.json"),
            )
            .await?,
            benchmark_campaigns: DocumentStore::open(root.join("benchmark_campaigns.json")).await?,
            benchmark_baselines: DocumentStore::open(root.join("benchmark_baselines.json")).await?,
            benchmark_results: DocumentStore::open(root.join("benchmark_results.json")).await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            state_root: root,
        };
        service.normalize_host_evidence_classes().await?;
        service.normalize_claim_decision_tier_fields().await?;
        service
            .normalize_claim_decision_benchmark_ready_scenarios()
            .await?;
        service
            .normalize_claim_decision_publication_scope_annotations()
            .await?;
        service
            .ingest_generated_validation_artifacts(state_root)
            .await?;
        Ok(service)
    }

    async fn create_host_evidence(
        &self,
        request: CreateHostEvidenceRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let evidence_mode = normalize_host_evidence_mode(&request.evidence_mode)?;
        let host_platform = normalize_host_platform(&request.host_platform)?;
        let execution_environment =
            normalize_execution_environment(&request.execution_environment)?;
        let host_class = derive_observe_host_class(&host_platform, &execution_environment);
        let host_class_evidence_key = canonical_host_class_evidence_key(&host_class)?;
        let note = normalize_optional_note(request.note)?;
        let id = UvmHostEvidenceId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate host evidence id")
                .with_detail(error.to_string())
        })?;
        let record = UvmHostEvidenceRecord {
            id: id.clone(),
            evidence_mode,
            host_platform,
            host_class,
            host_class_evidence_key,
            execution_environment,
            hardware_virtualization: request.hardware_virtualization,
            nested_virtualization: request.nested_virtualization,
            qemu_available: request.qemu_available,
            note,
            collected_at: OffsetDateTime::now_utc(),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.host_evidence
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "uvm.observe.host_evidence.recorded.v1",
            "uvm_host_evidence",
            id.as_str(),
            "created",
            serde_json::json!({
                "evidence_mode": record.evidence_mode,
                "host_platform": record.host_platform,
                "host_class": record.host_class,
                "host_class_evidence_key": record.host_class_evidence_key,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn list_host_evidence(&self) -> Result<Vec<UvmHostEvidenceRecord>> {
        let mut rows = self
            .host_evidence
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.collected_at
                .cmp(&right.collected_at)
                .then(left.id.cmp(&right.id))
        });
        Ok(rows)
    }

    async fn normalize_host_evidence_classes(&self) -> Result<()> {
        let mut rows = self.host_evidence.list().await?;
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        for (key, stored) in rows {
            if stored.deleted {
                continue;
            }

            let mut record = stored.value.clone();
            let normalized_host_platform = normalize_host_platform(&record.host_platform)?;
            let normalized_execution_environment =
                normalize_execution_environment(&record.execution_environment)?;
            let derived_host_class = derive_observe_host_class(
                &normalized_host_platform,
                &normalized_execution_environment,
            );
            let derived_host_class_evidence_key =
                canonical_host_class_evidence_key(&derived_host_class)?;

            let mut changed = false;
            if record.host_platform != normalized_host_platform {
                record.host_platform = normalized_host_platform;
                changed = true;
            }
            if record.execution_environment != normalized_execution_environment {
                record.execution_environment = normalized_execution_environment;
                changed = true;
            }
            if record.host_class != derived_host_class {
                record.host_class = derived_host_class;
                changed = true;
            }
            if record.host_class_evidence_key != derived_host_class_evidence_key {
                record.host_class_evidence_key = derived_host_class_evidence_key;
                changed = true;
            }

            if changed {
                self.host_evidence
                    .upsert(&key, record, Some(stored.version))
                    .await?;
            }
        }
        Ok(())
    }

    async fn normalize_claim_decision_tier_fields(&self) -> Result<()> {
        let mut rows = self.claim_decisions.list().await?;
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        for (key, stored) in rows {
            if stored.deleted {
                continue;
            }

            let mut record = stored.value.clone();
            let resolved_observed_highest_claim_tier = resolve_claim_decision_claim_tier(
                &record.observed_highest_claim_tier,
                &record.metadata,
                "observed_highest_claim_tier",
                &record.highest_claim_tier,
            )?;
            let resolved_benchmark_claim_tier_ceiling = resolve_claim_decision_claim_tier(
                &record.benchmark_claim_tier_ceiling,
                &record.metadata,
                "benchmark_claim_tier_ceiling",
                &record.highest_claim_tier,
            )?;

            let mut changed = false;
            if record.observed_highest_claim_tier != resolved_observed_highest_claim_tier {
                record.observed_highest_claim_tier = resolved_observed_highest_claim_tier;
                changed = true;
            }
            if record.benchmark_claim_tier_ceiling != resolved_benchmark_claim_tier_ceiling {
                record.benchmark_claim_tier_ceiling = resolved_benchmark_claim_tier_ceiling;
                changed = true;
            }

            if changed {
                self.claim_decisions
                    .upsert(&key, record, Some(stored.version))
                    .await?;
            }
        }
        Ok(())
    }

    async fn normalize_claim_decision_benchmark_ready_scenarios(&self) -> Result<()> {
        let mut rows = self.claim_decisions.list().await?;
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        for (key, stored) in rows {
            if stored.deleted {
                continue;
            }

            let mut record = stored.value.clone();
            let resolved_benchmark_ready_scenarios =
                resolve_claim_decision_benchmark_ready_scenarios(
                    &record.benchmark_ready_scenarios,
                    &record.metadata,
                );

            if record.benchmark_ready_scenarios != resolved_benchmark_ready_scenarios {
                record.benchmark_ready_scenarios = resolved_benchmark_ready_scenarios;
                self.claim_decisions
                    .upsert(&key, record, Some(stored.version))
                    .await?;
            }
        }
        Ok(())
    }

    async fn normalize_claim_decision_publication_scope_annotations(&self) -> Result<()> {
        let mut rows = self.claim_decisions.list().await?;
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        for (key, stored) in rows {
            if stored.deleted {
                continue;
            }

            let mut record = stored.value.clone();
            let publication_scope =
                resolve_publication_scope(record.portability_assessment.as_ref(), None, None)?;
            if publication_scope.apply_metadata_annotations(&mut record.metadata) {
                self.claim_decisions
                    .upsert(&key, record, Some(stored.version))
                    .await?;
            }
        }
        Ok(())
    }

    async fn ingest_generated_validation_artifacts(&self, state_root: &Path) -> Result<()> {
        let Some(manifest_path) = find_generated_validation_manifest_path(state_root) else {
            return Ok(());
        };
        let workspace_root = generated_validation_workspace_root(&manifest_path)?;
        let manifest = parse_generated_validation_manifest(&manifest_path)?;
        let mut reports = Vec::new();
        let mut seen_targets = BTreeSet::new();
        for entry in &manifest.artifacts {
            if entry.kind != "validation_report" {
                continue;
            }
            let report =
                generated_validation_report_from_manifest_entry(&workspace_root, &manifest, entry)?;
            if !seen_targets.insert(report.target.clone()) {
                return Err(PlatformError::invalid(
                    "generated validation manifest contains duplicate targets",
                )
                .with_detail(report.target));
            }
            reports.push(report);
        }
        reports.sort_by(|left, right| {
            left.target
                .cmp(&right.target)
                .then(left.artifact_path.cmp(&right.artifact_path))
        });
        for report in &reports {
            let campaign = self.upsert_generated_validation_campaign(report).await?;
            for scenario in &report.scenarios {
                let claim = if scenario.observe_engine == "qemu" {
                    &report.qemu_claim
                } else {
                    &report.uvm_claim
                };
                self.upsert_generated_validation_baseline(&campaign, report, scenario, claim)
                    .await?;
                self.upsert_generated_validation_result(&campaign, report, scenario, claim)
                    .await?;
            }
        }
        Ok(())
    }

    async fn upsert_generated_validation_campaign(
        &self,
        report: &GeneratedValidationReport,
    ) -> Result<UvmBenchmarkCampaignRecord> {
        let storage_key = generated_validation_campaign_storage_key(&report.target);
        let existing = self.benchmark_campaigns.get(&storage_key).await?;
        let id = match existing.as_ref() {
            Some(stored) => stored.value.id.clone(),
            None => UvmBenchmarkCampaignId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate benchmark campaign id")
                    .with_detail(error.to_string())
            })?,
        };
        let metadata = generated_validation_metadata(
            id.as_str(),
            existing.as_ref().map(|stored| &stored.value.metadata),
            report.generated_at,
            &format!(
                "generated-validation:campaign:v1|{}|{}|{}|{}|{}|{}",
                report.target,
                report.workload_class,
                report
                    .scenarios
                    .iter()
                    .any(|scenario| scenario.observe_engine == "qemu"),
                report
                    .scenarios
                    .iter()
                    .any(|scenario| scenario.observe_engine == "container"),
                report.artifact_path,
                report.artifact_sha256.as_deref().unwrap_or("-"),
            ),
            generated_validation_campaign_annotations(report),
        );
        let record = UvmBenchmarkCampaignRecord {
            id,
            name: generated_validation_campaign_name(&report.target),
            target: report.target.clone(),
            workload_class: report.workload_class.clone(),
            require_qemu_baseline: report
                .scenarios
                .iter()
                .any(|scenario| scenario.observe_engine == "qemu"),
            require_container_baseline: report
                .scenarios
                .iter()
                .any(|scenario| scenario.observe_engine == "container"),
            state: String::from("ready"),
            metadata,
        };
        match existing {
            Some(stored) if !stored.deleted && stored.value == record => Ok(stored.value),
            Some(stored) => {
                self.benchmark_campaigns
                    .upsert(&storage_key, record.clone(), Some(stored.version))
                    .await?;
                Ok(record)
            }
            None => {
                self.benchmark_campaigns
                    .upsert(&storage_key, record.clone(), None)
                    .await?;
                Ok(record)
            }
        }
    }

    async fn upsert_generated_validation_baseline(
        &self,
        campaign: &UvmBenchmarkCampaignRecord,
        report: &GeneratedValidationReport,
        scenario: &GeneratedValidationScenarioRow,
        claim: &GeneratedValidationClaimDescriptor,
    ) -> Result<()> {
        let measurement_scope = measured_benchmark_scope(
            Some(&report.host_class_evidence_key),
            &report.workload_class,
            &scenario.scenario,
            &scenario.observe_engine,
            true,
        )
        .ok_or_else(|| {
            PlatformError::invalid("generated validation baseline scope is incomplete").with_detail(
                format!(
                    "target={} scenario={} engine={}",
                    report.target, scenario.scenario, scenario.observe_engine
                ),
            )
        })?;
        let comparison_lineage = measured_benchmark_comparison_lineage(
            report.guest_run_lineage.as_deref(),
            Some(&scenario.measurement_mode),
            true,
        )
        .ok_or_else(|| {
            PlatformError::invalid("generated validation baseline lineage is incomplete")
                .with_detail(format!(
                    "target={} scenario={} engine={}",
                    report.target, scenario.scenario, scenario.observe_engine
                ))
        })?;
        let storage_key = benchmark_measurement_storage_key(&measurement_scope);
        let existing = self.benchmark_baselines.get(&storage_key).await?;
        if let Some(stored) = existing.as_ref()
            && !stored.deleted
            && Self::benchmark_baseline_comparison_lineage(&stored.value).as_ref()
                != Some(&comparison_lineage)
        {
            return Err(PlatformError::conflict(
                "generated validation baseline scope already exists with different comparison lineage",
            )
            .with_detail(format!(
                "scope={} existing={} generated={}",
                benchmark_measurement_scope_descriptor(&measurement_scope),
                Self::benchmark_baseline_comparison_lineage(&stored.value)
                    .as_ref()
                    .map(benchmark_comparison_lineage_descriptor)
                    .unwrap_or_else(|| String::from("unscoped")),
                benchmark_comparison_lineage_descriptor(&comparison_lineage),
            )));
        }
        let id = match existing.as_ref() {
            Some(stored) => stored.value.id.clone(),
            None => UvmBenchmarkBaselineId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate benchmark baseline id")
                    .with_detail(error.to_string())
            })?,
        };
        let metadata = generated_validation_metadata(
            id.as_str(),
            existing.as_ref().map(|stored| &stored.value.metadata),
            report.generated_at,
            &format!(
                "generated-validation:baseline:v1|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                campaign.id,
                report.target,
                report.host_class_evidence_key,
                report.workload_class,
                scenario.scenario,
                scenario.observe_engine,
                report.guest_run_lineage.as_deref().unwrap_or("host_scope"),
                scenario.measurement_mode,
                claim.evidence_mode,
                claim.claim_tier,
                scenario.boot_time_ms,
                scenario.steady_state_score,
                scenario.control_plane_p99_ms,
                scenario.backend.as_deref().unwrap_or("-"),
                report.artifact_path,
                report.artifact_sha256.as_deref().unwrap_or("-"),
            ),
            generated_validation_row_annotations(report, scenario, claim),
        );
        let record = UvmBenchmarkBaselineRecord {
            id,
            campaign_id: campaign.id.clone(),
            host_class_evidence_key: Some(report.host_class_evidence_key.clone()),
            workload_class: report.workload_class.clone(),
            scenario: scenario.scenario.clone(),
            guest_run_lineage: report.guest_run_lineage.clone(),
            measurement_mode: Some(scenario.measurement_mode.clone()),
            engine: scenario.observe_engine.clone(),
            evidence_mode: claim.evidence_mode.clone(),
            measured: true,
            boot_time_ms: Some(scenario.boot_time_ms),
            steady_state_score: Some(scenario.steady_state_score),
            control_plane_p99_ms: Some(scenario.control_plane_p99_ms),
            host_evidence_id: None,
            note: generated_validation_row_note(report, scenario, claim)?,
            metadata,
        };
        match existing {
            Some(stored) if !stored.deleted && stored.value == record => Ok(()),
            Some(stored) => self
                .benchmark_baselines
                .upsert(&storage_key, record, Some(stored.version))
                .await
                .map(|_| ()),
            None => self
                .benchmark_baselines
                .upsert(&storage_key, record, None)
                .await
                .map(|_| ()),
        }
    }

    async fn upsert_generated_validation_result(
        &self,
        campaign: &UvmBenchmarkCampaignRecord,
        report: &GeneratedValidationReport,
        scenario: &GeneratedValidationScenarioRow,
        claim: &GeneratedValidationClaimDescriptor,
    ) -> Result<()> {
        let measurement_scope = measured_benchmark_scope(
            Some(&report.host_class_evidence_key),
            &report.workload_class,
            &scenario.scenario,
            &scenario.observe_engine,
            true,
        )
        .ok_or_else(|| {
            PlatformError::invalid("generated validation result scope is incomplete").with_detail(
                format!(
                    "target={} scenario={} engine={}",
                    report.target, scenario.scenario, scenario.observe_engine
                ),
            )
        })?;
        let comparison_lineage = measured_benchmark_comparison_lineage(
            report.guest_run_lineage.as_deref(),
            Some(&scenario.measurement_mode),
            true,
        )
        .ok_or_else(|| {
            PlatformError::invalid("generated validation result lineage is incomplete").with_detail(
                format!(
                    "target={} scenario={} engine={}",
                    report.target, scenario.scenario, scenario.observe_engine
                ),
            )
        })?;
        let storage_key = benchmark_measurement_storage_key(&measurement_scope);
        let existing = self.benchmark_results.get(&storage_key).await?;
        if let Some(stored) = existing.as_ref()
            && !stored.deleted
            && Self::benchmark_result_comparison_lineage(&stored.value).as_ref()
                != Some(&comparison_lineage)
        {
            return Err(PlatformError::conflict(
                "generated validation result scope already exists with different comparison lineage",
            )
            .with_detail(format!(
                "scope={} existing={} generated={}",
                benchmark_measurement_scope_descriptor(&measurement_scope),
                Self::benchmark_result_comparison_lineage(&stored.value)
                    .as_ref()
                    .map(benchmark_comparison_lineage_descriptor)
                    .unwrap_or_else(|| String::from("unscoped")),
                benchmark_comparison_lineage_descriptor(&comparison_lineage),
            )));
        }
        let id = match existing.as_ref() {
            Some(stored) => stored.value.id.clone(),
            None => UvmBenchmarkResultId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate benchmark result id")
                    .with_detail(error.to_string())
            })?,
        };
        let metadata = generated_validation_metadata(
            id.as_str(),
            existing.as_ref().map(|stored| &stored.value.metadata),
            report.generated_at,
            &format!(
                "generated-validation:result:v1|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                campaign.id,
                report.target,
                report.host_class_evidence_key,
                report.workload_class,
                scenario.scenario,
                scenario.observe_engine,
                report.guest_run_lineage.as_deref().unwrap_or("host_scope"),
                scenario.measurement_mode,
                claim.evidence_mode,
                claim.claim_tier,
                scenario.boot_time_ms,
                scenario.steady_state_score,
                scenario.control_plane_p99_ms,
                scenario.backend.as_deref().unwrap_or("-"),
                report.artifact_path,
                report.artifact_sha256.as_deref().unwrap_or("-"),
            ),
            generated_validation_row_annotations(report, scenario, claim),
        );
        let record = UvmBenchmarkResultRecord {
            id,
            campaign_id: campaign.id.clone(),
            host_class_evidence_key: Some(report.host_class_evidence_key.clone()),
            workload_class: report.workload_class.clone(),
            guest_run_lineage: report.guest_run_lineage.clone(),
            measurement_mode: Some(scenario.measurement_mode.clone()),
            engine: scenario.observe_engine.clone(),
            scenario: scenario.scenario.clone(),
            evidence_mode: claim.evidence_mode.clone(),
            measured: true,
            boot_time_ms: scenario.boot_time_ms,
            steady_state_score: scenario.steady_state_score,
            control_plane_p99_ms: scenario.control_plane_p99_ms,
            host_evidence_id: None,
            note: generated_validation_row_note(report, scenario, claim)?,
            metadata,
        };
        match existing {
            Some(stored) if !stored.deleted && stored.value == record => Ok(()),
            Some(stored) => self
                .benchmark_results
                .upsert(&storage_key, record, Some(stored.version))
                .await
                .map(|_| ()),
            None => self
                .benchmark_results
                .upsert(&storage_key, record, None)
                .await
                .map(|_| ()),
        }
    }

    async fn resolve_host_evidence_record(
        &self,
        host_evidence_id: Option<String>,
    ) -> Result<Option<UvmHostEvidenceRecord>> {
        let Some(host_evidence_id) = host_evidence_id else {
            return Ok(None);
        };
        let host_evidence_id = UvmHostEvidenceId::parse(host_evidence_id).map_err(|error| {
            PlatformError::invalid("invalid host_evidence_id").with_detail(error.to_string())
        })?;
        let stored = self
            .host_evidence
            .get(host_evidence_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("host evidence does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("host evidence does not exist"));
        }
        Ok(Some(stored.value))
    }

    fn benchmark_baseline_measurement_scope(
        baseline: &UvmBenchmarkBaselineRecord,
    ) -> Option<BenchmarkMeasurementScope> {
        measured_benchmark_scope(
            baseline.host_class_evidence_key.as_deref(),
            &baseline.workload_class,
            &baseline.scenario,
            &baseline.engine,
            baseline.measured,
        )
    }

    fn benchmark_baseline_comparison_lineage(
        baseline: &UvmBenchmarkBaselineRecord,
    ) -> Option<BenchmarkComparisonLineage> {
        measured_benchmark_comparison_lineage(
            baseline.guest_run_lineage.as_deref(),
            baseline.measurement_mode.as_deref(),
            baseline.measured,
        )
    }

    fn benchmark_baseline_comparison_key(
        baseline: &UvmBenchmarkBaselineRecord,
    ) -> Option<BenchmarkComparisonKey> {
        Some(BenchmarkComparisonKey {
            scope: Self::benchmark_baseline_measurement_scope(baseline)?,
            lineage: Self::benchmark_baseline_comparison_lineage(baseline)?,
        })
    }

    fn benchmark_result_measurement_scope(
        result: &UvmBenchmarkResultRecord,
    ) -> Option<BenchmarkMeasurementScope> {
        measured_benchmark_scope(
            result.host_class_evidence_key.as_deref(),
            &result.workload_class,
            &result.scenario,
            &result.engine,
            result.measured,
        )
    }

    fn benchmark_result_comparison_lineage(
        result: &UvmBenchmarkResultRecord,
    ) -> Option<BenchmarkComparisonLineage> {
        measured_benchmark_comparison_lineage(
            result.guest_run_lineage.as_deref(),
            result.measurement_mode.as_deref(),
            result.measured,
        )
    }

    fn benchmark_result_comparison_key(
        result: &UvmBenchmarkResultRecord,
    ) -> Option<BenchmarkComparisonKey> {
        Some(BenchmarkComparisonKey {
            scope: Self::benchmark_result_measurement_scope(result)?,
            lineage: Self::benchmark_result_comparison_lineage(result)?,
        })
    }

    fn benchmark_claim_proof_key(
        key: &BenchmarkComparisonKey,
    ) -> Option<(String, BenchmarkClaimProofKey)> {
        if key.lineage.measurement_mode != MeasurementMode::Direct.as_str() {
            return None;
        }
        match key.scope.engine.as_str() {
            "software_dbt" | "qemu" => Some((
                key.scope.engine.clone(),
                BenchmarkClaimProofKey {
                    workload_class: key.scope.workload_class.clone(),
                    scenario: key.scope.scenario.clone(),
                    guest_run_lineage: key.lineage.guest_run_lineage.clone(),
                },
            )),
            _ => None,
        }
    }

    async fn benchmark_claim_proof_index(
        &self,
        host_class_evidence_key: Option<&str>,
    ) -> Result<BTreeMap<String, BenchmarkClaimProofAvailability>> {
        let Some(host_class_evidence_key) = host_class_evidence_key else {
            return Ok(BTreeMap::new());
        };
        let baseline_keys = self
            .list_benchmark_baselines()
            .await?
            .into_iter()
            .filter_map(|baseline| {
                let key = Self::benchmark_baseline_comparison_key(&baseline)?;
                (key.scope.host_class_evidence_key == host_class_evidence_key).then_some(key)
            })
            .collect::<BTreeSet<_>>();
        let result_keys = self
            .list_benchmark_results()
            .await?
            .into_iter()
            .filter_map(|result| {
                let key = Self::benchmark_result_comparison_key(&result)?;
                (key.scope.host_class_evidence_key == host_class_evidence_key).then_some(key)
            })
            .collect::<BTreeSet<_>>();

        let ready_keys = baseline_keys
            .intersection(&result_keys)
            .cloned()
            .collect::<Vec<_>>();
        let mut software_ready = BTreeSet::new();
        let mut qemu_ready = BTreeSet::new();
        for key in &ready_keys {
            let Some((engine, proof_key)) = Self::benchmark_claim_proof_key(key) else {
                continue;
            };
            match engine.as_str() {
                "software_dbt" => {
                    software_ready.insert(proof_key);
                }
                "qemu" => {
                    qemu_ready.insert(proof_key);
                }
                _ => {}
            }
        }

        let mut index = BTreeMap::new();
        for proof_key in software_ready.intersection(&qemu_ready) {
            index
                .entry(proof_key.workload_class.clone())
                .or_insert_with(BenchmarkClaimProofAvailability::default)
                .ready_scenarios
                .insert(proof_key.scenario.clone());
        }
        Ok(index)
    }

    async fn list_claim_decisions(&self) -> Result<Vec<UvmClaimDecisionRecord>> {
        let mut rows = self
            .claim_decisions
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.decided_at
                .cmp(&right.decided_at)
                .then(left.id.cmp(&right.id))
        });
        Ok(rows)
    }

    async fn latest_host_evidence(&self) -> Result<Option<UvmHostEvidenceRecord>> {
        let mut rows = self.list_host_evidence().await?;
        Ok(rows.pop())
    }

    fn preflight_evidence_artifact_from_record(
        preflight: &NodeRuntimePreflightPortabilityRecord,
    ) -> Result<Option<UvmPreflightEvidenceArtifact>> {
        let scoped_publication_scope =
            scoped_image_publication_scope(preflight.portability_assessment.as_ref())?;
        let fallback_axes = preflight_host_axes(preflight)?;
        let host_platform = fallback_axes
            .as_ref()
            .map(|(host_platform, _, _)| host_platform.clone())
            .or_else(|| {
                scoped_publication_scope
                    .as_ref()
                    .and_then(|scope| host_platform_from_host_class(&scope.host_class))
            });
        let host_class = scoped_publication_scope
            .as_ref()
            .map(|scope| scope.host_class.clone())
            .or_else(|| {
                fallback_axes
                    .as_ref()
                    .map(|(_, host_class, _)| host_class.clone())
            });
        let evidence_mode = fallback_axes
            .as_ref()
            .and_then(|(_, _, evidence_mode)| evidence_mode.clone());
        let Some(host_platform) = host_platform else {
            return Ok(None);
        };
        let Some(host_class) = host_class else {
            return Ok(None);
        };
        let host_class_evidence_key = canonical_host_class_evidence_key(&host_class)?;
        Ok(Some(UvmPreflightEvidenceArtifact {
            id: preflight.id.clone(),
            runtime_preflight_id: preflight.id.clone(),
            host_platform,
            host_class,
            host_class_evidence_key,
            evidence_mode,
            claim_tier: scoped_publication_scope
                .as_ref()
                .map(|scope| scope.claim_tier.clone())
                .unwrap_or_else(|| preflight.claim_tier.clone()),
            guest_architecture: preflight.guest_architecture.clone(),
            machine_family: scoped_publication_scope
                .as_ref()
                .map(|scope| scope.machine_family.clone())
                .unwrap_or_else(|| preflight.machine_family.clone()),
            guest_profile: scoped_publication_scope
                .as_ref()
                .map(|scope| scope.guest_profile.clone())
                .unwrap_or_else(|| preflight.guest_profile.clone()),
            selected_backend: scoped_publication_scope
                .as_ref()
                .and_then(|scope| scope.selected_backend.clone())
                .or_else(|| preflight.selected_backend.clone()),
            compatibility_assessment: preflight.compatibility_assessment.clone(),
            portability_assessment: preflight.portability_assessment.clone(),
            created_at: preflight.created_at,
        }))
    }

    async fn list_preflight_evidence_artifacts(&self) -> Result<Vec<UvmPreflightEvidenceArtifact>> {
        let mut rows = Vec::new();
        for (_, stored) in self.runtime_preflights.list().await? {
            if stored.deleted {
                continue;
            }
            if let Some(artifact) = Self::preflight_evidence_artifact_from_record(&stored.value)? {
                rows.push(artifact);
            }
        }
        rows.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then(left.runtime_preflight_id.cmp(&right.runtime_preflight_id))
        });
        Ok(rows)
    }

    async fn preflight_evidence_artifact(
        &self,
        runtime_preflight_id: &AuditId,
    ) -> Result<Option<UvmPreflightEvidenceArtifact>> {
        let Some(stored) = self
            .runtime_preflights
            .get(runtime_preflight_id.as_str())
            .await?
        else {
            return Ok(None);
        };
        if stored.deleted {
            return Ok(None);
        }
        Self::preflight_evidence_artifact_from_record(&stored.value)
    }

    async fn runtime_session_link_is_authoritative(
        &self,
        runtime_session_id: &UvmRuntimeSessionId,
        instance_id: &UvmInstanceId,
    ) -> Result<bool> {
        let Some(stored) = self
            .runtime_sessions
            .get(runtime_session_id.as_str())
            .await?
        else {
            return Ok(false);
        };
        Ok(!stored.deleted && stored.value.instance_id == *instance_id)
    }

    async fn latest_runtime_session_intent_for_instance(
        &self,
        instance_id: &UvmInstanceId,
    ) -> Result<Option<NodeRuntimeSessionIntentLineageRecord>> {
        let mut selected: Option<NodeRuntimeSessionIntentLineageRecord> = None;
        for (_, stored) in self.runtime_session_intents.list().await? {
            if stored.deleted || stored.value.instance_id != *instance_id {
                continue;
            }

            let value = stored.value;
            if !self
                .runtime_session_link_is_authoritative(&value.runtime_session_id, instance_id)
                .await?
            {
                continue;
            }
            let candidate_key = (
                value
                    .created_at
                    .map(OffsetDateTime::unix_timestamp_nanos)
                    .unwrap_or(i128::MIN),
                value.runtime_session_id.to_string(),
            );
            let selected_key = selected.as_ref().map(|current| {
                (
                    current
                        .created_at
                        .map(OffsetDateTime::unix_timestamp_nanos)
                        .unwrap_or(i128::MIN),
                    current.runtime_session_id.to_string(),
                )
            });
            if selected_key
                .map(|current| candidate_key > current)
                .unwrap_or(true)
            {
                selected = Some(value);
            }
        }
        Ok(selected)
    }

    async fn latest_runtime_session_intent_for_preflight(
        &self,
        runtime_preflight_id: &AuditId,
    ) -> Result<Option<NodeRuntimeSessionIntentLineageRecord>> {
        let mut selected: Option<NodeRuntimeSessionIntentLineageRecord> = None;
        for (_, stored) in self.runtime_session_intents.list().await? {
            if stored.deleted
                || stored.value.last_portability_preflight_id.as_ref() != Some(runtime_preflight_id)
            {
                continue;
            }

            let value = stored.value;
            if !self
                .runtime_session_link_is_authoritative(
                    &value.runtime_session_id,
                    &value.instance_id,
                )
                .await?
            {
                continue;
            }
            let candidate_key = (
                value
                    .created_at
                    .map(OffsetDateTime::unix_timestamp_nanos)
                    .unwrap_or(i128::MIN),
                value.runtime_session_id.to_string(),
            );
            let selected_key = selected.as_ref().map(|current| {
                (
                    current
                        .created_at
                        .map(OffsetDateTime::unix_timestamp_nanos)
                        .unwrap_or(i128::MIN),
                    current.runtime_session_id.to_string(),
                )
            });
            if selected_key
                .map(|current| candidate_key > current)
                .unwrap_or(true)
            {
                selected = Some(value);
            }
        }
        Ok(selected)
    }

    async fn resolve_runtime_session_lineage_portability(
        &self,
        lineage: NodeRuntimeSessionIntentLineageRecord,
    ) -> Result<Option<RuntimeLineagePortabilityResolution>> {
        let NodeRuntimeSessionIntentLineageRecord {
            runtime_session_id,
            instance_id,
            first_placement_portability_assessment,
            last_portability_preflight_id,
            created_at: _,
            ..
        } = lineage;
        if !self
            .runtime_session_link_is_authoritative(&runtime_session_id, &instance_id)
            .await?
        {
            return Ok(None);
        }
        if let Some(portability_assessment) = first_placement_portability_assessment {
            return Ok(Some(RuntimeLineagePortabilityResolution {
                instance_id,
                runtime_session_id,
                runtime_preflight_id: None,
                portability_assessment,
                source: UvmPortabilityAssessmentSource::FirstPlacementLineage,
            }));
        }

        let Some(runtime_preflight_id) = last_portability_preflight_id else {
            return Ok(None);
        };
        let Some(stored) = self
            .runtime_preflights
            .get(runtime_preflight_id.as_str())
            .await?
        else {
            return Ok(None);
        };
        if stored.deleted {
            return Ok(None);
        }
        let Some(portability_assessment) = stored.value.portability_assessment else {
            return Ok(None);
        };
        Ok(Some(RuntimeLineagePortabilityResolution {
            instance_id,
            runtime_session_id,
            runtime_preflight_id: Some(runtime_preflight_id),
            portability_assessment,
            source: UvmPortabilityAssessmentSource::LinkedRuntimePreflightLineage,
        }))
    }

    async fn resolve_runtime_lineage_portability_assessments(
        &self,
        perf_samples: &[UvmPerfAttestationRecord],
    ) -> Result<Vec<RuntimeLineagePortabilityResolution>> {
        let mut instance_ids = BTreeMap::new();
        for sample in perf_samples {
            instance_ids.insert(sample.instance_id.to_string(), sample.instance_id.clone());
        }

        let mut resolved = Vec::new();
        for instance_id in instance_ids.into_values() {
            let Some(lineage) = self
                .latest_runtime_session_intent_for_instance(&instance_id)
                .await?
            else {
                continue;
            };
            let Some(resolution) = self
                .resolve_runtime_session_lineage_portability(lineage)
                .await?
            else {
                continue;
            };
            resolved.push(RuntimeLineagePortabilityResolution {
                instance_id,
                ..resolution
            });
        }
        Ok(resolved)
    }

    async fn resolve_perf_sample_portability_assessment(
        &self,
        perf_samples: &[UvmPerfAttestationRecord],
        fallback_assessment: Option<UvmPortabilityAssessment>,
    ) -> Result<ResolvedClaimDecisionPortability> {
        let distinct_instance_ids = perf_samples
            .iter()
            .map(|sample| sample.instance_id.to_string())
            .collect::<BTreeSet<_>>();
        if distinct_instance_ids.len() == 1
            && let Some(instance_id) = perf_samples
                .first()
                .map(|sample| sample.instance_id.clone())
            && let Some(lineage) = self
                .latest_runtime_session_intent_for_instance(&instance_id)
                .await?
        {
            let runtime_session_id = Some(lineage.runtime_session_id.clone());
            if let Some(resolution) = self
                .resolve_runtime_session_lineage_portability(lineage)
                .await?
            {
                return Ok(ResolvedClaimDecisionPortability {
                    runtime_session_id: Some(resolution.runtime_session_id),
                    runtime_preflight_id: resolution.runtime_preflight_id,
                    portability_assessment: Some(resolution.portability_assessment),
                    source: resolution.source,
                });
            }

            let source = fallback_portability_source(fallback_assessment.as_ref());
            return Ok(ResolvedClaimDecisionPortability {
                runtime_session_id,
                runtime_preflight_id: None,
                portability_assessment: fallback_assessment,
                source,
            });
        }

        let source = fallback_portability_source(fallback_assessment.as_ref());
        Ok(ResolvedClaimDecisionPortability {
            runtime_session_id: None,
            runtime_preflight_id: None,
            portability_assessment: fallback_assessment,
            source,
        })
    }

    async fn resolve_claim_decision_portability_unavailable_reason(
        &self,
        runtime_session_id: Option<&UvmRuntimeSessionId>,
    ) -> Result<(
        Option<AuditId>,
        Option<UvmPortabilityAssessmentUnavailableReason>,
    )> {
        let Some(runtime_session_id) = runtime_session_id else {
            return Ok((None, None));
        };
        let Some(stored) = self
            .runtime_session_intents
            .get(runtime_session_id.as_str())
            .await?
        else {
            return Ok((None, None));
        };
        if stored.deleted {
            return Ok((None, None));
        }
        let lineage = stored.value;
        if !self
            .runtime_session_link_is_authoritative(
                &lineage.runtime_session_id,
                &lineage.instance_id,
            )
            .await?
        {
            return Ok((None, None));
        }
        Ok((
            lineage.last_portability_preflight_id,
            Some(
                UvmPortabilityAssessmentUnavailableReason::AuthoritativeRuntimeLineageMissingPortabilityEvidence,
            ),
        ))
    }

    async fn resolve_native_claim_status_portability_unavailable_reason(
        &self,
        perf_samples: &[UvmPerfAttestationRecord],
        runtime_session_id: Option<&UvmRuntimeSessionId>,
    ) -> Result<(
        Option<AuditId>,
        Option<UvmPortabilityAssessmentUnavailableReason>,
    )> {
        let Some(runtime_session_id) = runtime_session_id else {
            return Ok((None, None));
        };
        let distinct_instance_ids = perf_samples
            .iter()
            .map(|sample| sample.instance_id.to_string())
            .collect::<BTreeSet<_>>();
        if distinct_instance_ids.len() != 1 {
            return Ok((None, None));
        }
        let Some(instance_id) = perf_samples
            .first()
            .map(|sample| sample.instance_id.clone())
        else {
            return Ok((None, None));
        };
        let Some(lineage) = self
            .latest_runtime_session_intent_for_instance(&instance_id)
            .await?
        else {
            return Ok((None, None));
        };
        if lineage.runtime_session_id != *runtime_session_id {
            return Ok((None, None));
        }
        Ok((
            lineage.last_portability_preflight_id,
            Some(
                UvmPortabilityAssessmentUnavailableReason::AuthoritativeRuntimeLineageMissingPortabilityEvidence,
            ),
        ))
    }

    async fn resolve_runtime_preflight_portability_assessment(
        &self,
        runtime_preflight_id: &AuditId,
    ) -> Result<Option<UvmPortabilityAssessment>> {
        let stored = self
            .runtime_preflights
            .get(runtime_preflight_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("runtime preflight does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("runtime preflight does not exist"));
        }
        Ok(stored.value.portability_assessment)
    }

    async fn resolve_claim_decision_portability_assessment(
        &self,
        runtime_preflight_id: Option<String>,
        request_assessment: Option<UvmPortabilityAssessment>,
    ) -> Result<ResolvedClaimDecisionPortability> {
        if let Some(runtime_preflight_id) = runtime_preflight_id {
            let runtime_preflight_id = AuditId::parse(runtime_preflight_id).map_err(|error| {
                PlatformError::invalid("invalid runtime_preflight_id")
                    .with_detail(error.to_string())
            })?;
            let stored_portability_assessment = self
                .resolve_runtime_preflight_portability_assessment(&runtime_preflight_id)
                .await?;
            if let Some(lineage) = self
                .latest_runtime_session_intent_for_preflight(&runtime_preflight_id)
                .await?
            {
                let runtime_session_id = Some(lineage.runtime_session_id.clone());
                if let Some(resolution) = self
                    .resolve_runtime_session_lineage_portability(lineage)
                    .await?
                {
                    return Ok(ResolvedClaimDecisionPortability {
                        runtime_session_id: Some(resolution.runtime_session_id),
                        runtime_preflight_id: Some(runtime_preflight_id),
                        portability_assessment: Some(resolution.portability_assessment),
                        source: resolution.source,
                    });
                }

                let source = runtime_preflight_fallback_portability_source(
                    stored_portability_assessment.as_ref(),
                    request_assessment.as_ref(),
                );
                let portability_assessment = stored_portability_assessment.or(request_assessment);
                return Ok(ResolvedClaimDecisionPortability {
                    runtime_session_id,
                    runtime_preflight_id: Some(runtime_preflight_id),
                    source,
                    portability_assessment,
                });
            }

            let source = runtime_preflight_fallback_portability_source(
                stored_portability_assessment.as_ref(),
                request_assessment.as_ref(),
            );
            let portability_assessment = stored_portability_assessment.or(request_assessment);
            return Ok(ResolvedClaimDecisionPortability {
                runtime_session_id: None,
                runtime_preflight_id: Some(runtime_preflight_id),
                source,
                portability_assessment,
            });
        }

        let latest_perf_samples = Self::latest_perf_samples(self.active_perf_attestations().await?);
        self.resolve_perf_sample_portability_assessment(&latest_perf_samples, request_assessment)
            .await
    }

    async fn create_benchmark_campaign(
        &self,
        request: CreateBenchmarkCampaignRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let name = normalize_token(&request.name, "name", 128)?;
        let target = normalize_benchmark_target(&request.target)?;
        let workload_class = normalize_token(
            &request.workload_class,
            "workload_class",
            MAX_WORKLOAD_CLASS_LEN,
        )?;
        let id = UvmBenchmarkCampaignId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate benchmark campaign id")
                .with_detail(error.to_string())
        })?;
        let record = UvmBenchmarkCampaignRecord {
            id: id.clone(),
            name,
            target,
            workload_class,
            require_qemu_baseline: request.require_qemu_baseline.unwrap_or(true),
            require_container_baseline: request.require_container_baseline.unwrap_or(true),
            state: String::from("draft"),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.benchmark_campaigns
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "uvm.observe.benchmark_campaign.created.v1",
            "uvm_benchmark_campaign",
            id.as_str(),
            "created",
            serde_json::json!({
                "target": record.target,
                "workload_class": record.workload_class,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn list_benchmark_campaigns(&self) -> Result<Vec<UvmBenchmarkCampaignRecord>> {
        let mut rows = self
            .benchmark_campaigns
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
        Ok(rows)
    }

    async fn resolve_benchmark_campaign(
        &self,
        campaign_id: &UvmBenchmarkCampaignId,
    ) -> Result<UvmBenchmarkCampaignRecord> {
        if let Some(stored) = self.benchmark_campaigns.get(campaign_id.as_str()).await?
            && !stored.deleted
        {
            return Ok(stored.value);
        }
        self.benchmark_campaigns
            .list()
            .await?
            .into_iter()
            .find_map(|(_, stored)| {
                (!stored.deleted && stored.value.id == *campaign_id).then_some(stored.value)
            })
            .ok_or_else(|| PlatformError::not_found("benchmark campaign does not exist"))
    }

    async fn create_benchmark_baseline(
        &self,
        request: CreateBenchmarkBaselineRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let campaign_id = UvmBenchmarkCampaignId::parse(request.campaign_id).map_err(|error| {
            PlatformError::invalid("invalid campaign_id").with_detail(error.to_string())
        })?;
        let campaign = self.resolve_benchmark_campaign(&campaign_id).await?;
        let engine = normalize_benchmark_engine(&request.engine)?;
        let scenario = normalize_optional_benchmark_scenario(request.scenario, request.measured)?;
        let guest_run_lineage = normalize_benchmark_guest_run_lineage(
            request.guest_run_lineage,
            &campaign.target,
            request.measured,
        )?;
        let measurement_mode =
            normalize_benchmark_measurement_mode(request.measurement_mode, request.measured)?;
        let evidence_mode = normalize_host_evidence_mode(&request.evidence_mode)?;
        let host_evidence = self
            .resolve_host_evidence_record(request.host_evidence_id)
            .await?;
        let host_class_evidence_key = if request.measured {
            Some(
                host_evidence
                    .as_ref()
                    .ok_or_else(|| {
                        PlatformError::invalid(
                            "measured benchmark baselines require host_evidence_id",
                        )
                    })?
                    .host_class_evidence_key
                    .clone(),
            )
        } else {
            host_evidence
                .as_ref()
                .map(|value| value.host_class_evidence_key.clone())
        };
        let workload_class = campaign.workload_class.clone();
        let measurement_scope = measured_benchmark_scope(
            host_class_evidence_key.as_deref(),
            &workload_class,
            &scenario,
            &engine,
            request.measured,
        );
        let comparison_lineage = measured_benchmark_comparison_lineage(
            guest_run_lineage.as_deref(),
            measurement_mode.as_deref(),
            request.measured,
        );
        let note = normalize_optional_note(request.note)?;
        let (id, storage_key, expected_version, action, status_code) = if let Some(scope) =
            measurement_scope.as_ref()
        {
            let storage_key = benchmark_measurement_storage_key(scope);
            match self.benchmark_baselines.get(&storage_key).await? {
                Some(stored) if !stored.deleted => {
                    if Self::benchmark_baseline_comparison_lineage(&stored.value)
                        != comparison_lineage
                    {
                        return Err(PlatformError::conflict(
                                "measured benchmark baseline tuple already exists with different comparison lineage",
                            )
                            .with_detail(format!(
                                "existing={} requested={}",
                                Self::benchmark_baseline_comparison_lineage(&stored.value)
                                    .as_ref()
                                    .map(benchmark_comparison_lineage_descriptor)
                                    .unwrap_or_else(|| String::from("unscoped")),
                                comparison_lineage
                                    .as_ref()
                                    .map(benchmark_comparison_lineage_descriptor)
                                    .unwrap_or_else(|| String::from("unscoped"))
                            )));
                    }
                    (
                        stored.value.id,
                        storage_key,
                        Some(stored.version),
                        "updated",
                        StatusCode::OK,
                    )
                }
                _ => (
                    UvmBenchmarkBaselineId::generate().map_err(|error| {
                        PlatformError::unavailable("failed to allocate benchmark baseline id")
                            .with_detail(error.to_string())
                    })?,
                    storage_key,
                    None,
                    "created",
                    StatusCode::CREATED,
                ),
            }
        } else {
            let id = UvmBenchmarkBaselineId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate benchmark baseline id")
                    .with_detail(error.to_string())
            })?;
            (
                id.clone(),
                id.to_string(),
                None,
                "created",
                StatusCode::CREATED,
            )
        };
        let record = UvmBenchmarkBaselineRecord {
            id: id.clone(),
            campaign_id,
            host_class_evidence_key,
            workload_class,
            scenario,
            guest_run_lineage,
            measurement_mode,
            engine,
            evidence_mode,
            measured: request.measured,
            boot_time_ms: request.boot_time_ms,
            steady_state_score: request.steady_state_score,
            control_plane_p99_ms: request.control_plane_p99_ms,
            host_evidence_id: host_evidence.as_ref().map(|value| value.id.clone()),
            note,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.benchmark_baselines
            .upsert(&storage_key, record.clone(), expected_version)
            .await?;
        self.append_event(
            "uvm.observe.benchmark_baseline.created.v1",
            "uvm_benchmark_baseline",
            id.as_str(),
            action,
            serde_json::json!({
                "campaign_id": record.campaign_id,
                "host_class_evidence_key": record.host_class_evidence_key,
                "workload_class": record.workload_class,
                "scenario": record.scenario,
                "guest_run_lineage": record.guest_run_lineage,
                "measurement_mode": record.measurement_mode,
                "engine": record.engine,
                "evidence_mode": record.evidence_mode,
            }),
            context,
        )
        .await?;
        json_response(status_code, &record)
    }

    async fn list_benchmark_baselines(&self) -> Result<Vec<UvmBenchmarkBaselineRecord>> {
        let mut rows = self
            .benchmark_baselines
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| left.engine.cmp(&right.engine).then(left.id.cmp(&right.id)));
        Ok(rows)
    }

    async fn list_benchmark_results(&self) -> Result<Vec<UvmBenchmarkResultRecord>> {
        let mut rows = self
            .benchmark_results
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.metadata
                .updated_at
                .cmp(&right.metadata.updated_at)
                .then(left.id.cmp(&right.id))
        });
        Ok(rows)
    }

    async fn evidence_summary(&self) -> Result<serde_json::Value> {
        let perf_attestations = self.active_perf_attestations().await?;
        let host_evidence = self.list_host_evidence().await?;
        let claim_decisions = self.list_claim_decisions().await?;
        let preflight_evidence_artifacts = self.list_preflight_evidence_artifacts().await?;
        let benchmark_results = self.list_benchmark_results().await?;
        let latest_result = benchmark_results.last().cloned();
        let latest_preflight_evidence_artifact = preflight_evidence_artifacts.last().cloned();
        let latest_result_json = latest_result.map(|result| {
            serde_json::json!({
                "id": result.id,
                "campaign_id": result.campaign_id,
                "host_class_evidence_key": result.host_class_evidence_key,
                "workload_class": result.workload_class,
                "guest_run_lineage": result.guest_run_lineage,
                "measurement_mode": result.measurement_mode,
                "engine": result.engine,
                "scenario": result.scenario,
                "evidence_mode": result.evidence_mode,
                "measured": result.measured,
                "boot_time_ms": result.boot_time_ms,
                "steady_state_score": result.steady_state_score,
                "control_plane_p99_ms": result.control_plane_p99_ms,
                "host_evidence_id": result.host_evidence_id,
                "note": result.note,
            })
        });
        let latest_preflight_artifact_json = latest_preflight_evidence_artifact.map(|artifact| {
            serde_json::json!({
                "id": artifact.id,
                "runtime_preflight_id": artifact.runtime_preflight_id,
                "host_platform": artifact.host_platform,
                "host_class": artifact.host_class,
                "host_class_evidence_key": artifact.host_class_evidence_key,
                "evidence_mode": artifact.evidence_mode,
                "claim_tier": artifact.claim_tier,
                "guest_architecture": artifact.guest_architecture,
                "machine_family": artifact.machine_family,
                "guest_profile": artifact.guest_profile,
                "selected_backend": artifact.selected_backend,
            })
        });
        let native_claim_status = self.native_claim_status().await?;
        Ok(serde_json::json!({
            "service": self.name(),
            "state_root": self.state_root,
            "perf_attestation_count": perf_attestations.len(),
            "host_evidence_count": host_evidence.len(),
            "claim_decision_count": claim_decisions.len(),
            "preflight_evidence_artifact_count": preflight_evidence_artifacts.len(),
            "benchmark_result_count": benchmark_results.len(),
            "latest_benchmark_result": latest_result_json,
            "latest_preflight_evidence_artifact": latest_preflight_artifact_json,
            "native_claim_status": native_claim_status,
        }))
    }

    async fn create_benchmark_result(
        &self,
        request: CreateBenchmarkResultRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let campaign_id = UvmBenchmarkCampaignId::parse(request.campaign_id).map_err(|error| {
            PlatformError::invalid("invalid campaign_id").with_detail(error.to_string())
        })?;
        let campaign = self.resolve_benchmark_campaign(&campaign_id).await?;
        let engine = normalize_benchmark_engine(&request.engine)?;
        let scenario = normalize_benchmark_scenario(&request.scenario)?;
        let guest_run_lineage = normalize_benchmark_guest_run_lineage(
            request.guest_run_lineage,
            &campaign.target,
            request.measured,
        )?;
        let measurement_mode =
            normalize_benchmark_measurement_mode(request.measurement_mode, request.measured)?;
        let evidence_mode = normalize_host_evidence_mode(&request.evidence_mode)?;
        let host_evidence = self
            .resolve_host_evidence_record(request.host_evidence_id)
            .await?;
        let host_class_evidence_key = if request.measured {
            Some(
                host_evidence
                    .as_ref()
                    .ok_or_else(|| {
                        PlatformError::invalid(
                            "measured benchmark results require host_evidence_id",
                        )
                    })?
                    .host_class_evidence_key
                    .clone(),
            )
        } else {
            host_evidence
                .as_ref()
                .map(|value| value.host_class_evidence_key.clone())
        };
        let workload_class = campaign.workload_class.clone();
        let measurement_scope = measured_benchmark_scope(
            host_class_evidence_key.as_deref(),
            &workload_class,
            &scenario,
            &engine,
            request.measured,
        );
        let comparison_lineage = measured_benchmark_comparison_lineage(
            guest_run_lineage.as_deref(),
            measurement_mode.as_deref(),
            request.measured,
        );
        let note = normalize_optional_note(request.note)?;
        let (id, storage_key, expected_version, action, status_code) = if let Some(scope) =
            measurement_scope.as_ref()
        {
            let storage_key = benchmark_measurement_storage_key(scope);
            match self.benchmark_results.get(&storage_key).await? {
                Some(stored) if !stored.deleted => {
                    if Self::benchmark_result_comparison_lineage(&stored.value)
                        != comparison_lineage
                    {
                        return Err(PlatformError::conflict(
                                "measured benchmark result tuple already exists with different comparison lineage",
                            )
                            .with_detail(format!(
                                "existing={} requested={}",
                                Self::benchmark_result_comparison_lineage(&stored.value)
                                    .as_ref()
                                    .map(benchmark_comparison_lineage_descriptor)
                                    .unwrap_or_else(|| String::from("unscoped")),
                                comparison_lineage
                                    .as_ref()
                                    .map(benchmark_comparison_lineage_descriptor)
                                    .unwrap_or_else(|| String::from("unscoped"))
                            )));
                    }
                    (
                        stored.value.id,
                        storage_key,
                        Some(stored.version),
                        "updated",
                        StatusCode::OK,
                    )
                }
                _ => (
                    UvmBenchmarkResultId::generate().map_err(|error| {
                        PlatformError::unavailable("failed to allocate benchmark result id")
                            .with_detail(error.to_string())
                    })?,
                    storage_key,
                    None,
                    "created",
                    StatusCode::CREATED,
                ),
            }
        } else {
            let id = UvmBenchmarkResultId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate benchmark result id")
                    .with_detail(error.to_string())
            })?;
            (
                id.clone(),
                id.to_string(),
                None,
                "created",
                StatusCode::CREATED,
            )
        };
        let record = UvmBenchmarkResultRecord {
            id: id.clone(),
            campaign_id,
            host_class_evidence_key,
            workload_class,
            guest_run_lineage,
            measurement_mode,
            engine,
            scenario,
            evidence_mode,
            measured: request.measured,
            boot_time_ms: request.boot_time_ms,
            steady_state_score: request.steady_state_score,
            control_plane_p99_ms: request.control_plane_p99_ms,
            host_evidence_id: host_evidence.as_ref().map(|value| value.id.clone()),
            note,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.benchmark_results
            .upsert(&storage_key, record.clone(), expected_version)
            .await?;
        self.append_event(
            "uvm.observe.benchmark_result.created.v1",
            "uvm_benchmark_result",
            id.as_str(),
            action,
            serde_json::json!({
                "campaign_id": record.campaign_id,
                "host_class_evidence_key": record.host_class_evidence_key,
                "workload_class": record.workload_class,
                "guest_run_lineage": record.guest_run_lineage,
                "measurement_mode": record.measurement_mode,
                "engine": record.engine,
                "scenario": record.scenario,
            }),
            context,
        )
        .await?;
        json_response(status_code, &record)
    }

    async fn benchmark_summary(&self, campaign_id: &str) -> Result<serde_json::Value> {
        let campaign_id =
            UvmBenchmarkCampaignId::parse(campaign_id.to_owned()).map_err(|error| {
                PlatformError::invalid("invalid campaign_id").with_detail(error.to_string())
            })?;
        let campaign = self.resolve_benchmark_campaign(&campaign_id).await?;
        let baselines = self
            .list_benchmark_baselines()
            .await?
            .into_iter()
            .filter(|value| value.campaign_id == campaign_id)
            .collect::<Vec<_>>();
        let results = self
            .list_benchmark_results()
            .await?
            .into_iter()
            .filter(|value| value.campaign_id == campaign_id)
            .collect::<Vec<_>>();

        let mut required_engines = vec![String::from("software_dbt")];
        if campaign.require_qemu_baseline {
            required_engines.push(String::from("qemu"));
        }
        if campaign.require_container_baseline {
            required_engines.push(String::from("container"));
        }
        let guest_run_lineage_required =
            benchmark_target_requires_guest_run_lineage(&campaign.target);
        let comparison_alignment_descriptor =
            |host_class_evidence_key: Option<&str>,
             workload_class: &str,
             scenario: &str,
             engine: &str,
             guest_run_lineage: Option<&str>,
             measurement_mode: Option<&str>| {
                let guest_run_lineage = if guest_run_lineage_required {
                    guest_run_lineage.unwrap_or("missing")
                } else {
                    guest_run_lineage.unwrap_or("host_scope")
                };
                let workload_class = if workload_class.is_empty() {
                    "missing"
                } else {
                    workload_class
                };
                let scenario = if scenario.is_empty() {
                    "missing"
                } else {
                    scenario
                };
                format!(
                    "host_class={} workload_class={} scenario={} engine={} guest_run_lineage={} measurement_mode={}",
                    host_class_evidence_key.unwrap_or("missing"),
                    workload_class,
                    scenario,
                    engine,
                    guest_run_lineage,
                    measurement_mode.unwrap_or("missing"),
                )
            };
        let baseline_scope_index = baselines
            .iter()
            .filter_map(|baseline| {
                Self::benchmark_baseline_measurement_scope(baseline).map(|scope| (scope, baseline))
            })
            .collect::<BTreeMap<_, _>>();
        let baseline_comparison_index = baselines
            .iter()
            .filter_map(|baseline| {
                Self::benchmark_baseline_comparison_key(baseline).map(|key| (key, baseline))
            })
            .collect::<BTreeMap<_, _>>();
        let result_comparison_keys = results
            .iter()
            .filter_map(Self::benchmark_result_comparison_key)
            .collect::<BTreeSet<_>>();
        let mut missing_baselines = required_engines
            .iter()
            .filter(|engine| !baselines.iter().any(|baseline| &baseline.engine == *engine))
            .map(|engine| format!("engine={engine}"))
            .collect::<BTreeSet<_>>();
        let mut missing_results = required_engines
            .iter()
            .filter(|engine| !results.iter().any(|result| &result.engine == *engine))
            .map(|engine| format!("engine={engine}"))
            .collect::<BTreeSet<_>>();
        for result in &results {
            match Self::benchmark_result_comparison_key(result) {
                Some(key) => {
                    if !baseline_comparison_index.contains_key(&key) {
                        missing_baselines.insert(benchmark_comparison_key_descriptor(&key));
                    }
                }
                None if result.measured => {
                    missing_baselines.insert(comparison_alignment_descriptor(
                        result.host_class_evidence_key.as_deref(),
                        &result.workload_class,
                        &result.scenario,
                        &result.engine,
                        result.guest_run_lineage.as_deref(),
                        result.measurement_mode.as_deref(),
                    ));
                }
                None => {}
            }
        }
        for baseline in &baselines {
            match Self::benchmark_baseline_comparison_key(baseline) {
                Some(key) => {
                    if !result_comparison_keys.contains(&key) {
                        missing_results.insert(benchmark_comparison_key_descriptor(&key));
                    }
                }
                None if baseline.measured => {
                    missing_results.insert(comparison_alignment_descriptor(
                        baseline.host_class_evidence_key.as_deref(),
                        &baseline.workload_class,
                        &baseline.scenario,
                        &baseline.engine,
                        baseline.guest_run_lineage.as_deref(),
                        baseline.measurement_mode.as_deref(),
                    ));
                }
                None => {}
            }
        }
        let comparisons = results
            .iter()
            .map(|result| {
                let comparison_scope = Self::benchmark_result_measurement_scope(result);
                let comparison_lineage = Self::benchmark_result_comparison_lineage(result);
                let comparison_key = comparison_scope
                    .clone()
                    .zip(comparison_lineage.clone())
                    .map(|(scope, lineage)| BenchmarkComparisonKey { scope, lineage });
                let comparison_rejected_reason = if result.measured {
                    match comparison_key.as_ref() {
                        Some(key) => {
                            if baseline_comparison_index.contains_key(key) {
                                None
                            } else if let Some(baseline) = baseline_scope_index.get(&key.scope) {
                                match Self::benchmark_baseline_comparison_lineage(baseline) {
                                    Some(baseline_lineage) => Some(format!(
                                        "mixed comparison lineage rejected: baseline {} but result {}",
                                        benchmark_comparison_lineage_descriptor(&baseline_lineage),
                                        benchmark_comparison_lineage_descriptor(&key.lineage),
                                    )),
                                    None => Some(format!(
                                        "mixed comparison lineage rejected: baseline lacks explicit comparison lineage for {}",
                                        benchmark_measurement_scope_descriptor(&key.scope),
                                    )),
                                }
                            } else {
                                None
                            }
                        }
                        None => Some(format!(
                            "measured comparison lineage is incomplete: {}",
                            comparison_alignment_descriptor(
                                result.host_class_evidence_key.as_deref(),
                                &result.workload_class,
                                &result.scenario,
                                &result.engine,
                                result.guest_run_lineage.as_deref(),
                                result.measurement_mode.as_deref(),
                            )
                        )),
                    }
                } else {
                    None
                };
                let baseline = comparison_key
                    .as_ref()
                    .and_then(|key| baseline_comparison_index.get(key).copied())
                    .or_else(|| {
                        if !result.measured {
                            baselines.iter().find(|baseline| baseline.engine == result.engine)
                        } else {
                            None
                        }
                    });
                serde_json::json!({
                    "host_class_evidence_key": result.host_class_evidence_key,
                    "workload_class": result.workload_class,
                    "guest_run_lineage": result.guest_run_lineage,
                    "measurement_mode": result.measurement_mode,
                    "engine": result.engine,
                    "scenario": result.scenario,
                    "comparison_scope": comparison_scope.as_ref().map(benchmark_measurement_scope_descriptor),
                    "comparison_lineage": comparison_lineage.as_ref().map(benchmark_comparison_lineage_descriptor),
                    "comparison_rejected_reason": comparison_rejected_reason,
                    "baseline_present": baseline.is_some(),
                    "boot_time_delta_ms": baseline.and_then(|value| value.boot_time_ms).map(|baseline_value| i64::from(result.boot_time_ms) - i64::from(baseline_value)),
                    "steady_state_delta": baseline.and_then(|value| value.steady_state_score).map(|baseline_value| i64::from(result.steady_state_score) - i64::from(baseline_value)),
                    "control_plane_p99_delta_ms": baseline.and_then(|value| value.control_plane_p99_ms).map(|baseline_value| i64::from(result.control_plane_p99_ms) - i64::from(baseline_value)),
                })
            })
            .collect::<Vec<_>>();
        let status = if missing_baselines.is_empty() && missing_results.is_empty() {
            "ready"
        } else {
            "incomplete"
        };
        let missing_baselines = missing_baselines.into_iter().collect::<Vec<_>>();
        let missing_results = missing_results.into_iter().collect::<Vec<_>>();

        Ok(serde_json::json!({
            "campaign_id": campaign_id,
            "name": campaign.name,
            "target": campaign.target,
            "workload_class": campaign.workload_class,
            "required_engines": required_engines,
            "missing_baselines": missing_baselines,
            "missing_results": missing_results,
            "status": status,
            "comparisons": comparisons,
        }))
    }

    async fn create_perf_attestation(
        &self,
        request: CreatePerfAttestationRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let instance_id = UvmInstanceId::parse(request.instance_id).map_err(|error| {
            PlatformError::invalid("invalid instance_id").with_detail(error.to_string())
        })?;
        let workload_class = normalize_token(
            &request.workload_class,
            "workload_class",
            MAX_WORKLOAD_CLASS_LEN,
        )?;
        let claim_tier = normalize_claim_tier(request.claim_tier.as_deref())?;
        let claim_evidence_mode =
            normalize_claim_evidence_mode(request.claim_evidence_mode.as_deref())?;
        let cpu_overhead_pct = validate_percentage("cpu_overhead_pct", request.cpu_overhead_pct)?;
        let memory_overhead_pct =
            validate_percentage("memory_overhead_pct", request.memory_overhead_pct)?;
        let block_io_latency_overhead_pct = validate_percentage(
            "block_io_latency_overhead_pct",
            request.block_io_latency_overhead_pct,
        )?;
        let network_latency_overhead_pct = validate_percentage(
            "network_latency_overhead_pct",
            request.network_latency_overhead_pct,
        )?;
        let jitter_pct = validate_percentage("jitter_pct", request.jitter_pct)?;
        let fingerprint = perf_request_fingerprint(
            &instance_id,
            &workload_class,
            cpu_overhead_pct,
            memory_overhead_pct,
            block_io_latency_overhead_pct,
            network_latency_overhead_pct,
            jitter_pct,
        );

        if let Some(existing) = self.perf_attestations.get(&fingerprint).await?
            && !existing.deleted
        {
            return json_response(StatusCode::OK, &existing.value);
        }

        let native_indistinguishable = cpu_overhead_pct <= 5
            && memory_overhead_pct <= 5
            && block_io_latency_overhead_pct <= 10
            && network_latency_overhead_pct <= 10
            && jitter_pct <= 10;
        let id = UvmPerfAttestationId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate performance attestation id")
                .with_detail(error.to_string())
        })?;
        let record = UvmPerfAttestationRecord {
            id: id.clone(),
            instance_id,
            workload_class,
            claim_tier,
            claim_evidence_mode,
            cpu_overhead_pct,
            memory_overhead_pct,
            block_io_latency_overhead_pct,
            network_latency_overhead_pct,
            jitter_pct,
            native_indistinguishable,
            measured_at: OffsetDateTime::now_utc(),
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        match self
            .perf_attestations
            .create(&fingerprint, record.clone())
            .await
        {
            Ok(_) => {}
            Err(error) => {
                if let Some(existing) = self.perf_attestations.get(&fingerprint).await?
                    && !existing.deleted
                {
                    return json_response(StatusCode::OK, &existing.value);
                }
                return Err(error);
            }
        }
        self.append_event(
            "uvm.observe.perf_attested.v1",
            "uvm_perf_attestation",
            id.as_str(),
            "created",
            serde_json::json!({
                "native_indistinguishable": record.native_indistinguishable,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_failure_report(
        &self,
        request: CreateFailureReportRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let instance_id = request
            .instance_id
            .map(|value| {
                UvmInstanceId::parse(value).map_err(|error| {
                    PlatformError::invalid("invalid instance_id").with_detail(error.to_string())
                })
            })
            .transpose()?;
        let category = normalize_token(&request.category, "category", MAX_CATEGORY_LEN)?;
        let severity = normalize_severity(&request.severity)?;
        let summary = normalize_summary(&request.summary)?;
        let forensic_capture_requested = request.forensic_capture_requested.unwrap_or(false);
        let fingerprint = failure_report_fingerprint(
            instance_id.as_ref(),
            &category,
            &severity,
            &summary,
            request.recovered,
            forensic_capture_requested,
        );

        if let Some(existing) = self.failure_reports.get(&fingerprint).await?
            && !existing.deleted
        {
            return json_response(StatusCode::OK, &existing.value);
        }

        let id = UvmFailureReportId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate failure report id")
                .with_detail(error.to_string())
        })?;
        let record = UvmFailureReportRecord {
            id: id.clone(),
            instance_id,
            category,
            severity,
            summary,
            recovered: request.recovered,
            forensic_capture_requested,
            created_at: OffsetDateTime::now_utc(),
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        match self
            .failure_reports
            .create(&fingerprint, record.clone())
            .await
        {
            Ok(_) => {}
            Err(error) => {
                if let Some(existing) = self.failure_reports.get(&fingerprint).await?
                    && !existing.deleted
                {
                    return json_response(StatusCode::OK, &existing.value);
                }
                return Err(error);
            }
        }
        self.append_event(
            "uvm.observe.failure_reported.v1",
            "uvm_failure_report",
            id.as_str(),
            "created",
            serde_json::json!({
                "severity": record.severity,
                "recovered": record.recovered,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_claim_decision(
        &self,
        request: CreateClaimDecisionRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let host_evidence = match request.host_evidence_id {
            Some(value) => {
                let id = UvmHostEvidenceId::parse(value).map_err(|error| {
                    PlatformError::invalid("invalid host_evidence_id")
                        .with_detail(error.to_string())
                })?;
                let stored = self
                    .host_evidence
                    .get(id.as_str())
                    .await?
                    .ok_or_else(|| PlatformError::not_found("host evidence does not exist"))?;
                if stored.deleted {
                    return Err(PlatformError::not_found("host evidence does not exist"));
                }
                Some(stored.value)
            }
            None => self.latest_host_evidence().await?,
        };

        let ResolvedClaimDecisionPortability {
            runtime_session_id,
            runtime_preflight_id,
            portability_assessment,
            source,
        } = self
            .resolve_claim_decision_portability_assessment(
                request.runtime_preflight_id,
                request.portability_assessment,
            )
            .await?;
        let (runtime_preflight_id, portability_assessment_unavailable_reason) =
            if portability_assessment.is_none()
                && source == UvmPortabilityAssessmentSource::Unavailable
            {
                let (authoritative_runtime_preflight_id, unavailable_reason) = self
                    .resolve_claim_decision_portability_unavailable_reason(
                        runtime_session_id.as_ref(),
                    )
                    .await?;
                (
                    runtime_preflight_id.or(authoritative_runtime_preflight_id),
                    unavailable_reason,
                )
            } else {
                (runtime_preflight_id, None)
            };
        let linked_preflight_artifact = match runtime_preflight_id.as_ref() {
            Some(runtime_preflight_id) => {
                self.preflight_evidence_artifact(runtime_preflight_id)
                    .await?
            }
            None => None,
        };
        let publication_scope = resolve_publication_scope(
            portability_assessment.as_ref(),
            linked_preflight_artifact.as_ref(),
            host_evidence.as_ref(),
        )?;
        let publication_scope_host_class_evidence_key =
            publication_scope.host_class_evidence_key.clone();
        let mut evaluation = self
            .evaluate_claim_status(
                host_evidence.as_ref(),
                publication_scope_host_class_evidence_key.as_deref(),
            )
            .await?;
        evaluation.apply_portability_assessment(portability_assessment.as_ref());
        let id = UvmClaimDecisionId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate claim decision id")
                .with_detail(error.to_string())
        })?;
        let mut metadata = ResourceMetadata::new(
            OwnershipScope::Platform,
            Some(id.to_string()),
            sha256_hex(id.as_str().as_bytes()),
        );
        metadata.annotations.insert(
            String::from("observed_highest_claim_tier"),
            evaluation.observed_highest_claim_tier.clone(),
        );
        metadata.annotations.insert(
            String::from("benchmark_claim_tier_ceiling"),
            evaluation.benchmark_claim_tier_ceiling.clone(),
        );
        if evaluation.observed_highest_claim_tier != evaluation.highest_claim_tier {
            metadata.annotations.insert(
                String::from("claim_tier_demoted_from"),
                evaluation.observed_highest_claim_tier.clone(),
            );
        }
        if let Some(host_evidence) = host_evidence.as_ref() {
            metadata.annotations.insert(
                String::from("benchmark_host_class_evidence_key"),
                host_evidence.host_class_evidence_key.clone(),
            );
        }
        let _ = publication_scope.apply_metadata_annotations(&mut metadata);
        if !evaluation.benchmark_ready_scenarios.is_empty() {
            metadata.annotations.insert(
                String::from("benchmark_ready_scenarios"),
                evaluation.benchmark_ready_scenarios.join(","),
            );
        }
        let record = UvmClaimDecisionRecord {
            id: id.clone(),
            host_evidence_id: host_evidence.as_ref().map(|value| value.id.clone()),
            runtime_session_id,
            runtime_preflight_id,
            highest_claim_tier: evaluation.highest_claim_tier.clone(),
            observed_highest_claim_tier: evaluation.observed_highest_claim_tier.clone(),
            benchmark_claim_tier_ceiling: evaluation.benchmark_claim_tier_ceiling.clone(),
            benchmark_ready_scenarios: evaluation.benchmark_ready_scenarios.clone(),
            claim_status: evaluation.claim_status.clone(),
            native_indistinguishable_status: evaluation.native_indistinguishable_status,
            prohibited_claim_count: evaluation.prohibited_claim_count,
            missing_required_workload_classes: evaluation.missing_required_workload_classes.clone(),
            failing_workload_classes: evaluation.failing_workload_classes.clone(),
            portability_assessment: portability_assessment.clone(),
            portability_assessment_source: source,
            portability_assessment_unavailable_reason,
            decided_at: OffsetDateTime::now_utc(),
            metadata,
        };
        self.claim_decisions
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "uvm.observe.claim_decided.v1",
            "uvm_claim_decision",
            id.as_str(),
            "created",
            serde_json::json!({
                "claim_status": record.claim_status,
                "highest_claim_tier": record.highest_claim_tier,
                "observed_highest_claim_tier": record.observed_highest_claim_tier,
                "benchmark_claim_tier_ceiling": record.benchmark_claim_tier_ceiling,
                "prohibited_claim_count": record.prohibited_claim_count,
                "runtime_preflight_id": record.runtime_preflight_id.as_ref().map(|id| id.as_str()),
                "publication_scope_host_class_evidence_key": publication_scope_host_class_evidence_key,
                "publication_scope_region": publication_scope.region,
                "publication_scope_cell": publication_scope.cell,
                "publication_scope_backend": publication_scope.backend,
                "portability_supported": record
                    .portability_assessment
                    .as_ref()
                    .map(|assessment| assessment.supported),
                "portability_selected_backend": record
                    .portability_assessment
                    .as_ref()
                    .and_then(|assessment| assessment.selected_backend)
                    .map(|backend| backend.as_str()),
                "portability_assessment_source": record.portability_assessment_source.as_str(),
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn evaluate_claim_status(
        &self,
        host_evidence: Option<&UvmHostEvidenceRecord>,
        publication_scope_host_class_evidence_key: Option<&str>,
    ) -> Result<ClaimStatusEvaluation> {
        let perf_samples = Self::latest_perf_samples(self.active_perf_attestations().await?);
        let failure_samples = Self::unique_failure_samples(self.active_failure_reports().await?);
        let benchmark_claim_proofs = self
            .benchmark_claim_proof_index(publication_scope_host_class_evidence_key)
            .await?;
        let mut workload_classes = BTreeSet::new();
        let mut failing_workloads = BTreeSet::new();
        let mut benchmark_ready_scenarios = BTreeSet::new();
        let mut max_cpu = None;
        let mut max_memory = None;
        let mut max_block = None;
        let mut max_network = None;
        let mut max_jitter = None;
        let mut observed_highest_claim_tier = None;
        let mut highest_claim_tier = None;
        let mut benchmark_claim_tier_ceiling = None;

        for sample in &perf_samples {
            workload_classes.insert(sample.workload_class.clone());
            if !sample.native_indistinguishable {
                failing_workloads.insert(sample.workload_class.clone());
            }
            max_cpu = Some(max_cpu.unwrap_or(0).max(sample.cpu_overhead_pct));
            max_memory = Some(max_memory.unwrap_or(0).max(sample.memory_overhead_pct));
            max_block = Some(
                max_block
                    .unwrap_or(0)
                    .max(sample.block_io_latency_overhead_pct),
            );
            max_network = Some(
                max_network
                    .unwrap_or(0)
                    .max(sample.network_latency_overhead_pct),
            );
            max_jitter = Some(max_jitter.unwrap_or(0).max(sample.jitter_pct));

            let observed_tier = ClaimTier::parse(&sample.claim_tier)?;
            observed_highest_claim_tier = Some(strongest_claim_tier(
                observed_highest_claim_tier,
                observed_tier,
            ));

            let evidence_mode = parse_claim_evidence_mode(&sample.claim_evidence_mode)?;
            let benchmark_claim_proof = benchmark_claim_proofs
                .get(&sample.workload_class)
                .cloned()
                .unwrap_or_default();
            benchmark_ready_scenarios.extend(benchmark_claim_proof.ready_scenarios.iter().cloned());

            let publishable_claim_tier = strongest_publishable_claim_tier(
                observed_tier,
                evidence_mode,
                &benchmark_claim_proof,
            );
            highest_claim_tier = Some(strongest_claim_tier(
                highest_claim_tier,
                publishable_claim_tier,
            ));

            let claim_tier_ceiling = strongest_publishable_claim_tier(
                ClaimTier::FasterThanKvmForWorkloadClass,
                evidence_mode,
                &benchmark_claim_proof,
            );
            benchmark_claim_tier_ceiling = Some(strongest_claim_tier(
                benchmark_claim_tier_ceiling,
                claim_tier_ceiling,
            ));
        }

        let missing_required = REQUIRED_WORKLOAD_CLASSES
            .iter()
            .filter(|required| !workload_classes.contains(**required))
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        let native_ok =
            !perf_samples.is_empty() && missing_required.is_empty() && failing_workloads.is_empty();
        let prohibited_claims = perf_samples
            .iter()
            .filter(|sample| sample.claim_evidence_mode == ClaimEvidenceMode::Prohibited.as_str())
            .count() as u32;
        let observed_highest_claim_tier = observed_highest_claim_tier
            .unwrap_or(ClaimTier::Compatible)
            .as_str()
            .to_owned();
        let highest_claim_tier = highest_claim_tier
            .unwrap_or(ClaimTier::Compatible)
            .as_str()
            .to_owned();
        let benchmark_claim_tier_ceiling = benchmark_claim_tier_ceiling
            .unwrap_or(ClaimTier::Compatible)
            .as_str()
            .to_owned();
        let unrecovered_critical_count = failure_samples
            .iter()
            .filter(|sample| sample.severity == "critical" && !sample.recovered)
            .count();
        let critical_unrecovered = unrecovered_critical_count > 0;

        let claim_status =
            normalize_claim_status(if prohibited_claims > 0 || critical_unrecovered {
                "prohibited"
            } else if highest_claim_tier == ClaimTier::ResearchOnly.as_str() {
                "restricted"
            } else if host_evidence
                .map(|evidence| {
                    evidence.evidence_mode == ClaimEvidenceMode::Measured.as_str()
                        && native_ok
                        && !critical_unrecovered
                })
                .unwrap_or(false)
            {
                "allowed"
            } else {
                "restricted"
            })?;

        Ok(ClaimStatusEvaluation {
            native_indistinguishable_status: native_ok && !critical_unrecovered,
            perf_samples: perf_samples.len(),
            distinct_workload_classes: workload_classes.len(),
            missing_required_workload_classes: missing_required,
            failing_workload_classes: failing_workloads.into_iter().collect::<Vec<_>>(),
            observed_highest_claim_tier,
            highest_claim_tier,
            benchmark_claim_tier_ceiling,
            benchmark_ready_scenarios: benchmark_ready_scenarios.into_iter().collect::<Vec<_>>(),
            prohibited_claim_count: prohibited_claims,
            critical_unrecovered_failures: critical_unrecovered,
            unrecovered_critical_count,
            max_cpu,
            max_memory,
            max_block,
            max_network,
            max_jitter,
            claim_status,
        })
    }

    async fn native_claim_status(&self) -> Result<serde_json::Value> {
        let host_evidence = self.latest_host_evidence().await?;
        let latest_perf_samples = Self::latest_perf_samples(self.active_perf_attestations().await?);
        let runtime_lineage_portability = self
            .resolve_runtime_lineage_portability_assessments(&latest_perf_samples)
            .await?;
        let resolved_portability = self
            .resolve_perf_sample_portability_assessment(&latest_perf_samples, None)
            .await?;
        let ResolvedClaimDecisionPortability {
            runtime_session_id,
            runtime_preflight_id,
            portability_assessment,
            source,
        } = resolved_portability;
        let (runtime_preflight_id, portability_assessment_unavailable_reason) =
            if portability_assessment.is_none()
                && source == UvmPortabilityAssessmentSource::Unavailable
            {
                let (authoritative_runtime_preflight_id, unavailable_reason) = self
                    .resolve_native_claim_status_portability_unavailable_reason(
                        &latest_perf_samples,
                        runtime_session_id.as_ref(),
                    )
                    .await?;
                (
                    runtime_preflight_id.or(authoritative_runtime_preflight_id),
                    unavailable_reason,
                )
            } else {
                (runtime_preflight_id, None)
            };
        let linked_preflight_artifact = match runtime_preflight_id.as_ref() {
            Some(runtime_preflight_id) => {
                self.preflight_evidence_artifact(runtime_preflight_id)
                    .await?
            }
            None => None,
        };
        let publication_scope = resolve_publication_scope(
            portability_assessment.as_ref(),
            linked_preflight_artifact.as_ref(),
            host_evidence.as_ref(),
        )?;
        let publication_scope_host_class_evidence_key =
            publication_scope.host_class_evidence_key.clone();
        let mut evaluation = self
            .evaluate_claim_status(
                host_evidence.as_ref(),
                publication_scope_host_class_evidence_key.as_deref(),
            )
            .await?;
        evaluation.apply_portability_assessments(
            runtime_lineage_portability
                .iter()
                .map(|resolution| &resolution.portability_assessment),
        );

        Ok(serde_json::json!({
            "native_indistinguishable_status": evaluation.native_indistinguishable_status,
            "claim_status": evaluation.claim_status,
            "host_evidence_id": host_evidence.as_ref().map(|value| value.id.to_string()),
            "host_class_evidence_key": host_evidence
                .as_ref()
                .map(|value| value.host_class_evidence_key.clone()),
            "publication_scope_host_class_evidence_key": publication_scope_host_class_evidence_key,
            "publication_scope_region": publication_scope.region,
            "publication_scope_cell": publication_scope.cell,
            "publication_scope_backend": publication_scope.backend,
            "runtime_session_id": runtime_session_id.as_ref().map(|id| id.to_string()),
            "runtime_preflight_id": runtime_preflight_id.as_ref().map(|id| id.to_string()),
            "runtime_preflight_evidence_artifact_id": linked_preflight_artifact
                .as_ref()
                .map(|artifact| artifact.id.to_string()),
            "runtime_preflight_host_class_evidence_key": linked_preflight_artifact
                .as_ref()
                .map(|artifact| artifact.host_class_evidence_key.clone()),
            "portability_assessment": portability_assessment,
            "portability_assessment_source": source.as_str(),
            "portability_assessment_unavailable_reason": portability_assessment_unavailable_reason
                .map(UvmPortabilityAssessmentUnavailableReason::as_str),
            "perf_samples": evaluation.perf_samples,
            "distinct_workload_classes": evaluation.distinct_workload_classes,
            "missing_required_workload_classes": evaluation.missing_required_workload_classes,
            "failing_workload_classes": evaluation.failing_workload_classes,
            "observed_highest_claim_tier": evaluation.observed_highest_claim_tier,
            "highest_claim_tier": evaluation.highest_claim_tier,
            "benchmark_claim_tier_ceiling": evaluation.benchmark_claim_tier_ceiling,
            "benchmark_ready_scenarios": evaluation.benchmark_ready_scenarios,
            "prohibited_claim_count": evaluation.prohibited_claim_count,
            "critical_unrecovered_failures": evaluation.critical_unrecovered_failures,
            "unrecovered_critical_count": evaluation.unrecovered_critical_count,
            "max_overhead": if evaluation.perf_samples == 0 {
                serde_json::Value::Null
            } else {
                serde_json::json!({
                    "cpu_overhead_pct": evaluation.max_cpu,
                    "memory_overhead_pct": evaluation.max_memory,
                    "block_io_latency_overhead_pct": evaluation.max_block,
                    "network_latency_overhead_pct": evaluation.max_network,
                    "jitter_pct": evaluation.max_jitter,
                })
            },
        }))
    }

    async fn observe_summary(&self) -> Result<serde_json::Value> {
        let perf_samples = self.active_perf_attestations().await?;
        let failure_samples = self.active_failure_reports().await?;
        let native_claim_status = self.native_claim_status().await?;
        let preflight_evidence_artifacts = self.list_preflight_evidence_artifacts().await?;
        Ok(serde_json::json!({
            "service": self.name(),
            "state_root": self.state_root,
            "perf_attestation_count": perf_samples.len(),
            "failure_report_count": failure_samples.len(),
            "host_evidence_count": self.list_host_evidence().await?.len(),
            "claim_decision_count": self.list_claim_decisions().await?.len(),
            "preflight_evidence_artifact_count": preflight_evidence_artifacts.len(),
            "claim_tiers": perf_samples
                .iter()
                .map(|sample| sample.claim_tier.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>(),
            "native_claim_status": native_claim_status,
        }))
    }

    async fn active_perf_attestations(&self) -> Result<Vec<UvmPerfAttestationRecord>> {
        let mut values = self
            .perf_attestations
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            (
                left.instance_id.as_str(),
                left.workload_class.as_str(),
                left.measured_at.unix_timestamp_nanos(),
                left.id.as_str(),
            )
                .cmp(&(
                    right.instance_id.as_str(),
                    right.workload_class.as_str(),
                    right.measured_at.unix_timestamp_nanos(),
                    right.id.as_str(),
                ))
        });
        Ok(values)
    }

    async fn active_failure_reports(&self) -> Result<Vec<UvmFailureReportRecord>> {
        let mut values = self
            .failure_reports
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            (
                left.instance_id
                    .as_ref()
                    .map(UvmInstanceId::as_str)
                    .unwrap_or(""),
                left.category.as_str(),
                left.severity.as_str(),
                left.created_at.unix_timestamp_nanos(),
                left.id.as_str(),
            )
                .cmp(&(
                    right
                        .instance_id
                        .as_ref()
                        .map(UvmInstanceId::as_str)
                        .unwrap_or(""),
                    right.category.as_str(),
                    right.severity.as_str(),
                    right.created_at.unix_timestamp_nanos(),
                    right.id.as_str(),
                ))
        });
        Ok(values)
    }

    fn failure_fingerprint_for_record(record: &UvmFailureReportRecord) -> String {
        failure_report_fingerprint(
            record.instance_id.as_ref(),
            &record.category,
            &record.severity,
            &record.summary,
            record.recovered,
            record.forensic_capture_requested,
        )
    }

    fn latest_perf_samples(values: Vec<UvmPerfAttestationRecord>) -> Vec<UvmPerfAttestationRecord> {
        let mut latest: BTreeMap<(String, String), UvmPerfAttestationRecord> = BTreeMap::new();
        for record in values {
            let key = (
                record.instance_id.as_str().to_owned(),
                record.workload_class.clone(),
            );
            let replace = match latest.get(&key) {
                Some(existing) => {
                    record.measured_at > existing.measured_at
                        || (record.measured_at == existing.measured_at && record.id > existing.id)
                }
                None => true,
            };
            if replace {
                latest.insert(key, record);
            }
        }
        latest.into_values().collect()
    }

    fn unique_failure_samples(values: Vec<UvmFailureReportRecord>) -> Vec<UvmFailureReportRecord> {
        let mut seen = BTreeSet::new();
        values
            .into_iter()
            .filter(|record| seen.insert(Self::failure_fingerprint_for_record(record)))
            .collect()
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
        let correlation_id = context.correlation_id.clone();
        let event = PlatformEvent {
            header: EventHeader {
                event_id: AuditId::generate().map_err(|error| {
                    PlatformError::unavailable("failed to allocate audit id")
                        .with_detail(error.to_string())
                })?,
                event_type: event_type.to_owned(),
                schema_version: 1,
                source_service: String::from("uvm-observe"),
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
        let idempotency = sha256_hex(
            format!(
                "uvm-event:v1|{}|{}|{}|{}|{}|{}",
                event.header.event_type.as_str(),
                resource_kind,
                resource_id,
                action,
                correlation_id,
                details_json
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

impl HttpService for UvmObserveService {
    fn name(&self) -> &'static str {
        "uvm-observe"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] = &[
            uhost_runtime::RouteClaim::exact("/uvm/observe"),
            uhost_runtime::RouteClaim::exact("/uvm/observe/summary"),
            uhost_runtime::RouteClaim::prefix("/uvm/perf-attestations"),
            uhost_runtime::RouteClaim::prefix("/uvm/failure-reports"),
            uhost_runtime::RouteClaim::prefix("/uvm/host-evidence"),
            uhost_runtime::RouteClaim::prefix("/uvm/preflight-evidence-artifacts"),
            uhost_runtime::RouteClaim::prefix("/uvm/claim-decisions"),
            uhost_runtime::RouteClaim::prefix("/uvm/benchmark-campaigns"),
            uhost_runtime::RouteClaim::prefix("/uvm/benchmark-baselines"),
            uhost_runtime::RouteClaim::prefix("/uvm/benchmark-results"),
            uhost_runtime::RouteClaim::prefix("/uvm/native-claim-status"),
            uhost_runtime::RouteClaim::prefix("/uvm/observe-outbox"),
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
                (Method::GET, ["uvm", "observe", "summary"]) => {
                    let summary = self.evidence_summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["uvm", "observe"]) => {
                    let summary = self.observe_summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["uvm", "perf-attestations"]) => {
                    json_response(StatusCode::OK, &self.active_perf_attestations().await?).map(Some)
                }
                (Method::POST, ["uvm", "perf-attestations"]) => {
                    let body: CreatePerfAttestationRequest = parse_json(request).await?;
                    self.create_perf_attestation(body, &context).await.map(Some)
                }
                (Method::GET, ["uvm", "failure-reports"]) => {
                    json_response(StatusCode::OK, &self.active_failure_reports().await?).map(Some)
                }
                (Method::POST, ["uvm", "failure-reports"]) => {
                    let body: CreateFailureReportRequest = parse_json(request).await?;
                    self.create_failure_report(body, &context).await.map(Some)
                }
                (Method::GET, ["uvm", "host-evidence"]) => {
                    let values = self.list_host_evidence().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["uvm", "host-evidence"]) => {
                    let body: CreateHostEvidenceRequest = parse_json(request).await?;
                    self.create_host_evidence(body, &context).await.map(Some)
                }
                (Method::GET, ["uvm", "preflight-evidence-artifacts"]) => {
                    let values = self.list_preflight_evidence_artifacts().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["uvm", "claim-decisions"]) => {
                    let values = self.list_claim_decisions().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["uvm", "claim-decisions"]) => {
                    let body: CreateClaimDecisionRequest = parse_json(request).await?;
                    self.create_claim_decision(body, &context).await.map(Some)
                }
                (Method::GET, ["uvm", "benchmark-campaigns"]) => {
                    let values = self.list_benchmark_campaigns().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["uvm", "benchmark-campaigns", campaign_id, "summary"]) => {
                    let value = self.benchmark_summary(campaign_id).await?;
                    json_response(StatusCode::OK, &value).map(Some)
                }
                (Method::POST, ["uvm", "benchmark-campaigns"]) => {
                    let body: CreateBenchmarkCampaignRequest = parse_json(request).await?;
                    self.create_benchmark_campaign(body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["uvm", "benchmark-baselines"]) => {
                    let values = self.list_benchmark_baselines().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["uvm", "benchmark-baselines"]) => {
                    let body: CreateBenchmarkBaselineRequest = parse_json(request).await?;
                    self.create_benchmark_baseline(body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["uvm", "benchmark-results"]) => {
                    let values = self.list_benchmark_results().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["uvm", "benchmark-results"]) => {
                    let body: CreateBenchmarkResultRequest = parse_json(request).await?;
                    self.create_benchmark_result(body, &context).await.map(Some)
                }
                (Method::GET, ["uvm", "native-claim-status"]) => {
                    let value = self.native_claim_status().await?;
                    json_response(StatusCode::OK, &value).map(Some)
                }
                (Method::GET, ["uvm", "observe-outbox"]) => {
                    let values = self.outbox.list_all().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use http_body_util::BodyExt;
    use tempfile::tempdir;

    use super::{
        CreateBenchmarkBaselineRequest, CreateBenchmarkCampaignRequest,
        CreateBenchmarkResultRequest, CreateClaimDecisionRequest, CreateFailureReportRequest,
        CreateHostEvidenceRequest, CreatePerfAttestationRequest,
        NodeRuntimePreflightPortabilityRecord, NodeRuntimeSessionIntentLineageRecord,
        NodeRuntimeSessionPresenceRecord, REQUIRED_WORKLOAD_CLASSES, UvmBenchmarkBaselineRecord,
        UvmBenchmarkCampaignRecord, UvmBenchmarkResultRecord, UvmClaimDecisionRecord,
        UvmHostEvidenceRecord, UvmObserveService, UvmPreflightEvidenceArtifact,
    };
    use uhost_core::RequestContext;
    use uhost_store::DocumentStore;
    use uhost_types::{AuditId, EventPayload, UvmInstanceId, UvmRuntimeSessionId};
    use uhost_uvm::{
        BackendSelectionRequest, GuestArchitecture, HostPlatform, HypervisorBackend,
        UvmBackendFallbackPolicy, UvmCompatibilityAssessment, UvmCompatibilityEvidence,
        UvmCompatibilityEvidenceSource, UvmEvidenceStrictness, UvmExecutionIntent,
        UvmPortabilityAssessment, UvmPortabilityAssessmentSource,
        UvmPortabilityAssessmentUnavailableReason, UvmPortabilityTier, assess_execution_intent,
    };

    async fn response_json<T: serde::de::DeserializeOwned>(
        response: http::Response<uhost_api::ApiBody>,
    ) -> T {
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"))
    }

    fn assert_native_claim_status_portability(
        status: &serde_json::Value,
        portability_assessment: Option<&UvmPortabilityAssessment>,
        source: UvmPortabilityAssessmentSource,
        runtime_session_id: Option<&UvmRuntimeSessionId>,
        runtime_preflight_id: Option<&AuditId>,
        unavailable_reason: Option<UvmPortabilityAssessmentUnavailableReason>,
    ) {
        let expected_portability = portability_assessment
            .map(|assessment| {
                serde_json::to_value(assessment).unwrap_or_else(|error| panic!("{error}"))
            })
            .unwrap_or(serde_json::Value::Null);
        let expected_runtime_session_id = runtime_session_id
            .map(|id| serde_json::Value::String(id.to_string()))
            .unwrap_or(serde_json::Value::Null);
        let expected_runtime_preflight_id = runtime_preflight_id
            .map(|id| serde_json::Value::String(id.to_string()))
            .unwrap_or(serde_json::Value::Null);
        assert_eq!(status["runtime_session_id"], expected_runtime_session_id);
        assert_eq!(
            status["runtime_preflight_id"],
            expected_runtime_preflight_id
        );
        assert_eq!(status["portability_assessment"], expected_portability);
        assert_eq!(
            status["portability_assessment_source"].as_str(),
            Some(source.as_str())
        );
        let expected_unavailable_reason = unavailable_reason
            .map(|reason| serde_json::Value::String(reason.as_str().to_owned()))
            .unwrap_or(serde_json::Value::Null);
        assert_eq!(
            status["portability_assessment_unavailable_reason"],
            expected_unavailable_reason
        );
    }

    async fn create_perf_samples_with_claim_tier(
        service: &UvmObserveService,
        instance: &UvmInstanceId,
        context: &RequestContext,
        claim_tier: &str,
        claim_evidence_mode: &str,
    ) {
        for &workload_class in REQUIRED_WORKLOAD_CLASSES {
            let _ = service
                .create_perf_attestation(
                    CreatePerfAttestationRequest {
                        instance_id: instance.to_string(),
                        workload_class: workload_class.to_string(),
                        claim_tier: Some(claim_tier.to_owned()),
                        claim_evidence_mode: Some(claim_evidence_mode.to_owned()),
                        cpu_overhead_pct: 4,
                        memory_overhead_pct: 4,
                        block_io_latency_overhead_pct: 8,
                        network_latency_overhead_pct: 8,
                        jitter_pct: 7,
                    },
                    context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }
    }

    async fn create_strong_perf_samples(
        service: &UvmObserveService,
        instance: &UvmInstanceId,
        context: &RequestContext,
    ) {
        create_perf_samples_with_claim_tier(service, instance, context, "competitive", "measured")
            .await;
    }

    async fn create_measured_host_evidence(
        service: &UvmObserveService,
        context: &RequestContext,
    ) -> UvmHostEvidenceRecord {
        create_measured_host_evidence_for_environment(service, context, "bare_metal").await
    }

    async fn create_measured_host_evidence_for_environment(
        service: &UvmObserveService,
        context: &RequestContext,
        execution_environment: &str,
    ) -> UvmHostEvidenceRecord {
        let host_evidence = service
            .create_host_evidence(
                CreateHostEvidenceRequest {
                    evidence_mode: String::from("measured"),
                    host_platform: String::from("linux"),
                    execution_environment: String::from(execution_environment),
                    hardware_virtualization: true,
                    nested_virtualization: true,
                    qemu_available: true,
                    note: Some(String::from("benchmark host")),
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        response_json(host_evidence).await
    }

    fn scoped_image_compatibility_artifact_evidence(
        host_class: &str,
        claim_tier: &str,
        accelerator_backend: &str,
    ) -> UvmCompatibilityEvidence {
        UvmCompatibilityEvidence {
            source: UvmCompatibilityEvidenceSource::ImageContract,
            summary: format!(
                "scoped image compatibility artifact row_id=scope-row-1 host_class={host_class} region=global cell=global accelerator_backend={accelerator_backend} machine_family=general_purpose_pci guest_profile=linux_standard claim_tier={claim_tier} secure_boot_supported=true live_migration_supported=true policy_approved=true"
            ),
            evidence_mode: Some(String::from("policy_approved")),
        }
    }

    fn supported_portability_with_scoped_image_artifact(
        host_class: &str,
        claim_tier: &str,
        accelerator_backend: &str,
    ) -> UvmPortabilityAssessment {
        let mut portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt, HypervisorBackend::Kvm],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            None,
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        portability
            .evidence
            .push(scoped_image_compatibility_artifact_evidence(
                host_class,
                claim_tier,
                accelerator_backend,
            ));
        portability
    }

    async fn create_direct_benchmark_claim_proof(
        service: &UvmObserveService,
        context: &RequestContext,
        host_evidence: &UvmHostEvidenceRecord,
        workload_class: &str,
        scenarios: &[&str],
    ) {
        let campaign = service
            .create_benchmark_campaign(
                CreateBenchmarkCampaignRequest {
                    name: format!("claim-proof-{workload_class}"),
                    target: String::from("host"),
                    workload_class: String::from(workload_class),
                    require_qemu_baseline: Some(true),
                    require_container_baseline: Some(false),
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let campaign: UvmBenchmarkCampaignRecord = response_json(campaign).await;

        for engine in ["software_dbt", "qemu"] {
            for (index, scenario) in scenarios.iter().enumerate() {
                let boot_time_ms = if engine == "software_dbt" { 100 } else { 180 } + index as u32;
                let steady_state_score =
                    if engine == "software_dbt" { 900 } else { 780 } + index as u32;
                let control_plane_p99_ms =
                    if engine == "software_dbt" { 10 } else { 18 } + index as u32;
                let _ = service
                    .create_benchmark_baseline(
                        CreateBenchmarkBaselineRequest {
                            campaign_id: campaign.id.to_string(),
                            engine: String::from(engine),
                            scenario: Some((*scenario).to_owned()),
                            guest_run_lineage: None,
                            measurement_mode: Some(String::from("direct")),
                            evidence_mode: String::from("measured"),
                            measured: true,
                            boot_time_ms: Some(boot_time_ms),
                            steady_state_score: Some(steady_state_score),
                            control_plane_p99_ms: Some(control_plane_p99_ms),
                            host_evidence_id: Some(host_evidence.id.to_string()),
                            note: Some(format!("baseline {engine} {scenario}")),
                        },
                        context,
                    )
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                let _ = service
                    .create_benchmark_result(
                        CreateBenchmarkResultRequest {
                            campaign_id: campaign.id.to_string(),
                            engine: String::from(engine),
                            scenario: (*scenario).to_owned(),
                            guest_run_lineage: None,
                            measurement_mode: Some(String::from("direct")),
                            evidence_mode: String::from("measured"),
                            measured: true,
                            boot_time_ms: boot_time_ms.saturating_sub(3),
                            steady_state_score: steady_state_score + 5,
                            control_plane_p99_ms: control_plane_p99_ms.saturating_sub(1),
                            host_evidence_id: Some(host_evidence.id.to_string()),
                            note: Some(format!("result {engine} {scenario}")),
                        },
                        context,
                    )
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
            }
        }
    }

    fn generated_validation_ubuntu_report_markdown() -> String {
        String::from(
            r#"# UVM Validation Report

- Generated at: 2026-04-09 16:05:49.619701749 +00:00:00
- Target: `ubuntu_22_04_vm`
- Guest architecture: `x86_64`
- Host platform: `linux`
- Execution environment: `container_restricted`
- Measurement mode: `hybrid`
- QEMU available: `true`
- Nested virtualization available: `false`

## Comparison

- UVM claim tier: `research_only` (prohibited)
- QEMU claim tier: `compatible` (simulated)

## Scenario matrix

| Scenario | Engine | Evidence mode | Boot (ms) | Throughput | Control p99 (ms) | Notes |
| --- | --- | --- | ---: | ---: | ---: | --- |
| cold_boot | uvm | hybrid | 175.44 | 12517.45 | 18.74 | backend=software_dbt; target=ubuntu_22_04_vm; evidence_mode=hybrid |
| steady_state | uvm | hybrid | 154.38 | 13605.92 | 19.73 | backend=software_dbt; target=ubuntu_22_04_vm; evidence_mode=hybrid |
| migration_pressure | uvm | hybrid | 196.49 | 11428.98 | 24.46 | backend=software_dbt; target=ubuntu_22_04_vm; evidence_mode=hybrid |
| fault_recovery | uvm | hybrid | 207.01 | 10340.50 | 25.65 | backend=software_dbt; target=ubuntu_22_04_vm; evidence_mode=hybrid |
| cold_boot | qemu | hybrid | 667.58 | 9213.14 | 39.38 | backend=qemu-tcg-x86_64; target=ubuntu_22_04_vm; evidence_mode=hybrid |
| steady_state | qemu | hybrid | 587.47 | 10014.28 | 41.45 | backend=qemu-tcg-x86_64; target=ubuntu_22_04_vm; evidence_mode=hybrid |
| migration_pressure | qemu | hybrid | 747.69 | 8411.99 | 51.40 | backend=qemu-tcg-x86_64; target=ubuntu_22_04_vm; evidence_mode=hybrid |
| fault_recovery | qemu | hybrid | 787.74 | 7610.85 | 53.89 | backend=qemu-tcg-x86_64; target=ubuntu_22_04_vm; evidence_mode=hybrid |

## Stress phases
"#,
        )
    }

    fn generated_validation_host_report_markdown() -> String {
        String::from(
            r#"# UVM Validation Report

- Generated at: 2026-04-09 16:01:12.000000000 +00:00:00
- Target: `host`
- Guest architecture: `x86_64`
- Host platform: `linux`
- Execution environment: `bare_metal`
- Measurement mode: `direct`
- QEMU available: `true`
- Nested virtualization available: `true`

## Comparison

- UVM claim tier: `competitive` (measured)
- QEMU claim tier: `compatible` (simulated)

## Scenario matrix

| Scenario | Engine | Evidence mode | Boot (ms) | Throughput | Control p99 (ms) | Notes |
| --- | --- | --- | ---: | ---: | ---: | --- |
| cold_boot | uvm | direct | 89.11 | 14120.44 | 11.42 | backend=software_dbt; target=host; evidence_mode=direct |
| service_readiness | qemu | direct | 312.87 | 10015.12 | 23.68 | backend=qemu-kvm-x86_64; target=host; evidence_mode=direct |

## Stress phases
"#,
        )
    }

    fn write_generated_validation_bundle(workspace_root: &std::path::Path) {
        let generated_dir = workspace_root.join("docs/benchmarks/generated");
        std::fs::create_dir_all(&generated_dir).unwrap_or_else(|error| panic!("{error}"));

        let report = generated_validation_ubuntu_report_markdown();
        let report_path = generated_dir.join("ubuntu-validation.md");
        std::fs::write(&report_path, &report).unwrap_or_else(|error| panic!("{error}"));

        let installer_witness_path = generated_dir.join("ubuntu-26.04-installer-boot-witness.json");
        let disk_witness_path = generated_dir.join("ubuntu-26.04-disk-boot-witness.json");
        std::fs::write(&installer_witness_path, "{\"boot\":\"installer\"}\n")
            .unwrap_or_else(|error| panic!("{error}"));
        std::fs::write(&disk_witness_path, "{\"boot\":\"disk\"}\n")
            .unwrap_or_else(|error| panic!("{error}"));

        let manifest = serde_json::json!({
            "bundle": "wave3-core-generated-benchmark-evidence",
            "artifacts": [
                {
                    "path": "docs/benchmarks/generated/ubuntu-validation.md",
                    "kind": "validation_report",
                    "target": "ubuntu_22_04_vm",
                    "generated_at": "2026-04-09 16:05:49.619701749 +00:00:00",
                    "sha256": uhost_core::sha256_hex(report.as_bytes()),
                    "references": [
                        "docs/benchmarks/generated/ubuntu-26.04-installer-boot-witness.json",
                        "docs/benchmarks/generated/ubuntu-26.04-disk-boot-witness.json"
                    ]
                }
            ]
        });
        std::fs::write(
            generated_dir.join("uvm-stack-validation-manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
    }

    fn write_generated_validation_bundle_with_host_and_guest_reports(
        workspace_root: &std::path::Path,
    ) {
        let generated_dir = workspace_root.join("docs/benchmarks/generated");
        std::fs::create_dir_all(&generated_dir).unwrap_or_else(|error| panic!("{error}"));

        let host_report = generated_validation_host_report_markdown();
        let host_report_path = generated_dir.join("host-validation.md");
        std::fs::write(&host_report_path, &host_report).unwrap_or_else(|error| panic!("{error}"));

        let guest_report = generated_validation_ubuntu_report_markdown();
        let guest_report_path = generated_dir.join("ubuntu-validation.md");
        std::fs::write(&guest_report_path, &guest_report).unwrap_or_else(|error| panic!("{error}"));

        let installer_witness_path = generated_dir.join("ubuntu-26.04-installer-boot-witness.json");
        let disk_witness_path = generated_dir.join("ubuntu-26.04-disk-boot-witness.json");
        std::fs::write(&installer_witness_path, "{\"boot\":\"installer\"}\n")
            .unwrap_or_else(|error| panic!("{error}"));
        std::fs::write(&disk_witness_path, "{\"boot\":\"disk\"}\n")
            .unwrap_or_else(|error| panic!("{error}"));

        let manifest = serde_json::json!({
            "bundle": "wave3-core-generated-benchmark-evidence",
            "artifacts": [
                {
                    "path": "docs/benchmarks/generated/host-validation.md",
                    "kind": "validation_report",
                    "target": "host",
                    "generated_at": "2026-04-09 16:01:12.000000000 +00:00:00",
                    "sha256": uhost_core::sha256_hex(host_report.as_bytes()),
                    "references": []
                },
                {
                    "path": "docs/benchmarks/generated/ubuntu-validation.md",
                    "kind": "validation_report",
                    "target": "ubuntu_22_04_vm",
                    "generated_at": "2026-04-09 16:05:49.619701749 +00:00:00",
                    "sha256": uhost_core::sha256_hex(guest_report.as_bytes()),
                    "references": [
                        "docs/benchmarks/generated/ubuntu-26.04-installer-boot-witness.json",
                        "docs/benchmarks/generated/ubuntu-26.04-disk-boot-witness.json"
                    ]
                }
            ]
        });
        std::fs::write(
            generated_dir.join("uvm-stack-validation-manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn persist_runtime_preflight_portability_assessment(
        state_root: &std::path::Path,
        portability_assessment: Option<UvmPortabilityAssessment>,
    ) -> AuditId {
        let store = DocumentStore::open(state_root.join("uvm-node/runtime_preflights.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let record = NodeRuntimePreflightPortabilityRecord {
            id: id.clone(),
            guest_architecture: String::from("x86_64"),
            machine_family: String::from("general_purpose_pci"),
            guest_profile: String::from("linux_standard"),
            claim_tier: String::from("compatible"),
            selected_backend: None,
            compatibility_assessment: None,
            portability_assessment,
            created_at: time::OffsetDateTime::now_utc(),
            extra_fields: std::collections::BTreeMap::new(),
        };
        let _ = store
            .create(id.as_str(), record)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        id
    }

    async fn persist_runtime_preflight_artifact_source(
        state_root: &std::path::Path,
        host_platform: &str,
        host_class: &str,
        evidence_mode: Option<&str>,
        selected_backend: Option<&str>,
    ) -> AuditId {
        let store = DocumentStore::open(state_root.join("uvm-node/runtime_preflights.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let record = NodeRuntimePreflightPortabilityRecord {
            id: id.clone(),
            guest_architecture: String::from("x86_64"),
            machine_family: String::from("general_purpose_pci"),
            guest_profile: String::from("linux_standard"),
            claim_tier: String::from("competitive"),
            selected_backend: selected_backend.map(str::to_owned),
            compatibility_assessment: Some(UvmCompatibilityAssessment {
                requirement: uhost_uvm::UvmCompatibilityRequirement::parse_keys(
                    GuestArchitecture::X86_64,
                    "general_purpose_pci",
                    "linux_standard",
                    "disk",
                    "competitive",
                )
                .unwrap_or_else(|error| panic!("{error}")),
                supported: true,
                matched_backends: vec![HypervisorBackend::SoftwareDbt],
                blockers: Vec::new(),
                evidence: vec![UvmCompatibilityEvidence {
                    source: UvmCompatibilityEvidenceSource::NodeCapability,
                    summary: format!(
                        "host_class={} host_platform={} accelerator_backends=software_dbt supported_machine_families=general_purpose_pci supported_guest_profiles=linux_standard",
                        host_class, host_platform
                    ),
                    evidence_mode: evidence_mode.map(str::to_owned),
                }],
            }),
            portability_assessment: None,
            created_at: time::OffsetDateTime::now_utc(),
            extra_fields: std::collections::BTreeMap::new(),
        };
        let _ = store
            .create(id.as_str(), record)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        id
    }

    async fn persist_runtime_preflight_artifact_source_with_scoped_portability(
        state_root: &std::path::Path,
        host_platform: &str,
        fallback_host_class: &str,
        scoped_host_class: &str,
        scoped_claim_tier: &str,
        selected_backend: &str,
    ) -> AuditId {
        let store = DocumentStore::open(state_root.join("uvm-node/runtime_preflights.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let record = NodeRuntimePreflightPortabilityRecord {
            id: id.clone(),
            guest_architecture: String::from("x86_64"),
            machine_family: String::from("general_purpose_pci"),
            guest_profile: String::from("linux_standard"),
            claim_tier: String::from("compatible"),
            selected_backend: Some(String::from("software_dbt")),
            compatibility_assessment: Some(UvmCompatibilityAssessment {
                requirement: uhost_uvm::UvmCompatibilityRequirement::parse_keys(
                    GuestArchitecture::X86_64,
                    "general_purpose_pci",
                    "linux_standard",
                    "disk",
                    "compatible",
                )
                .unwrap_or_else(|error| panic!("{error}")),
                supported: true,
                matched_backends: vec![HypervisorBackend::SoftwareDbt],
                blockers: Vec::new(),
                evidence: vec![UvmCompatibilityEvidence {
                    source: UvmCompatibilityEvidenceSource::NodeCapability,
                    summary: format!(
                        "host_class={} host_platform={} accelerator_backends=software_dbt supported_machine_families=general_purpose_pci supported_guest_profiles=linux_standard",
                        fallback_host_class, host_platform
                    ),
                    evidence_mode: Some(String::from("measured")),
                }],
            }),
            portability_assessment: Some(supported_portability_with_scoped_image_artifact(
                scoped_host_class,
                scoped_claim_tier,
                selected_backend,
            )),
            created_at: time::OffsetDateTime::now_utc(),
            extra_fields: std::collections::BTreeMap::new(),
        };
        let _ = store
            .create(id.as_str(), record)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        id
    }

    async fn persist_runtime_session_intent_lineage(
        state_root: &std::path::Path,
        instance_id: &UvmInstanceId,
        last_portability_preflight_id: Option<AuditId>,
    ) -> UvmRuntimeSessionId {
        persist_runtime_session_intent_lineage_with_first_placement_portability(
            state_root,
            instance_id,
            None,
            last_portability_preflight_id,
        )
        .await
    }

    async fn persist_runtime_session_intent_lineage_with_first_placement_portability(
        state_root: &std::path::Path,
        instance_id: &UvmInstanceId,
        first_placement_portability_assessment: Option<UvmPortabilityAssessment>,
        last_portability_preflight_id: Option<AuditId>,
    ) -> UvmRuntimeSessionId {
        let runtime_sessions =
            DocumentStore::open(state_root.join("uvm-node/runtime_sessions.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let store = DocumentStore::open(state_root.join("uvm-node/runtime_session_intents.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id =
            UvmRuntimeSessionId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime_session = NodeRuntimeSessionPresenceRecord {
            id: runtime_session_id.clone(),
            instance_id: instance_id.clone(),
            extra_fields: std::collections::BTreeMap::new(),
        };
        let _ = runtime_sessions
            .create(runtime_session_id.as_str(), runtime_session)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let record = NodeRuntimeSessionIntentLineageRecord {
            runtime_session_id: runtime_session_id.clone(),
            instance_id: instance_id.clone(),
            first_placement_portability_assessment,
            last_portability_preflight_id,
            created_at: Some(time::OffsetDateTime::now_utc()),
            extra_fields: std::collections::BTreeMap::new(),
        };
        let _ = store
            .create(runtime_session_id.as_str(), record)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        runtime_session_id
    }

    async fn soft_delete_runtime_session_presence(
        state_root: &std::path::Path,
        runtime_session_id: &UvmRuntimeSessionId,
    ) {
        let store = DocumentStore::<NodeRuntimeSessionPresenceRecord>::open(
            state_root.join("uvm-node/runtime_sessions.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        store
            .soft_delete(runtime_session_id.as_str(), None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn soft_delete_runtime_session_intent_lineage(
        state_root: &std::path::Path,
        runtime_session_id: &UvmRuntimeSessionId,
    ) {
        let store = DocumentStore::<NodeRuntimeSessionIntentLineageRecord>::open(
            state_root.join("uvm-node/runtime_session_intents.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        store
            .soft_delete(runtime_session_id.as_str(), None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[tokio::test]
    async fn host_evidence_records_include_shared_host_class() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_host_evidence(
                CreateHostEvidenceRequest {
                    evidence_mode: String::from("measured"),
                    host_platform: String::from("linux"),
                    execution_environment: String::from("hosted_ci"),
                    hardware_virtualization: false,
                    nested_virtualization: false,
                    qemu_available: true,
                    note: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let record: UvmHostEvidenceRecord = response_json(created).await;
        assert_eq!(record.host_class, "linux_hosted_ci");
        assert_eq!(record.host_class_evidence_key, "linux_hosted_ci");
    }

    #[tokio::test]
    async fn runtime_preflight_evidence_artifact_derives_canonical_host_class_key() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let runtime_preflight_id = persist_runtime_preflight_artifact_source(
            temp.path(),
            "linux",
            "linux_bare_metal",
            Some("measured"),
            Some("kvm"),
        )
        .await;
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let artifacts = service
            .list_preflight_evidence_artifacts()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(artifacts.len(), 1);
        let artifact: &UvmPreflightEvidenceArtifact = &artifacts[0];
        assert_eq!(artifact.id, runtime_preflight_id);
        assert_eq!(artifact.runtime_preflight_id, runtime_preflight_id);
        assert_eq!(artifact.host_platform, "linux");
        assert_eq!(artifact.host_class, "linux_bare_metal");
        assert_eq!(artifact.host_class_evidence_key, "linux_bare_metal");
        assert_eq!(artifact.evidence_mode.as_deref(), Some("measured"));
        assert_eq!(artifact.claim_tier, "competitive");
        assert_eq!(artifact.guest_architecture, "x86_64");
        assert_eq!(artifact.machine_family, "general_purpose_pci");
        assert_eq!(artifact.guest_profile, "linux_standard");
        assert_eq!(artifact.selected_backend.as_deref(), Some("kvm"));
    }

    #[tokio::test]
    async fn runtime_preflight_evidence_artifact_prefers_scoped_portability_artifact_scope() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let runtime_preflight_id =
            persist_runtime_preflight_artifact_source_with_scoped_portability(
                temp.path(),
                "linux",
                "linux_hosted_ci",
                "linux_bare_metal",
                "competitive",
                "kvm",
            )
            .await;
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let artifacts = service
            .list_preflight_evidence_artifacts()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(artifacts.len(), 1);
        let artifact: &UvmPreflightEvidenceArtifact = &artifacts[0];
        assert_eq!(artifact.id, runtime_preflight_id);
        assert_eq!(artifact.host_platform, "linux");
        assert_eq!(artifact.host_class, "linux_bare_metal");
        assert_eq!(artifact.host_class_evidence_key, "linux_bare_metal");
        assert_eq!(artifact.claim_tier, "competitive");
        assert_eq!(artifact.selected_backend.as_deref(), Some("kvm"));
    }

    #[tokio::test]
    async fn native_claim_status_surfaces_preflight_evidence_artifact_key() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let runtime_preflight_id = persist_runtime_preflight_artifact_source(
            temp.path(),
            "linux",
            "linux_bare_metal",
            Some("measured"),
            Some("kvm"),
        )
        .await;
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        create_strong_perf_samples(&service, &instance, &context).await;
        let _host_evidence = create_measured_host_evidence(&service, &context).await;
        let _runtime_session_id = persist_runtime_session_intent_lineage(
            temp.path(),
            &instance,
            Some(runtime_preflight_id.clone()),
        )
        .await;

        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            status["runtime_preflight_evidence_artifact_id"].as_str(),
            Some(runtime_preflight_id.as_str())
        );
        assert_eq!(
            status["runtime_preflight_host_class_evidence_key"].as_str(),
            Some("linux_bare_metal")
        );
        assert_eq!(
            status["host_class_evidence_key"].as_str(),
            Some("linux_bare_metal")
        );
    }

    #[tokio::test]
    async fn native_claim_status_passes_for_strong_perf_samples() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        for &workload_class in REQUIRED_WORKLOAD_CLASSES {
            let _ = service
                .create_perf_attestation(
                    CreatePerfAttestationRequest {
                        instance_id: instance.to_string(),
                        workload_class: workload_class.to_string(),
                        claim_tier: None,
                        claim_evidence_mode: None,
                        cpu_overhead_pct: 4,
                        memory_overhead_pct: 4,
                        block_io_latency_overhead_pct: 8,
                        network_latency_overhead_pct: 8,
                        jitter_pct: 7,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }
        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            status["native_indistinguishable_status"]
                .as_bool()
                .unwrap_or(false)
        );
        assert_native_claim_status_portability(
            &status,
            None,
            UvmPortabilityAssessmentSource::Unavailable,
            None,
            None,
            None,
        );
    }

    #[tokio::test]
    async fn observe_summary_exposes_counts_and_native_status() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        for &workload_class in REQUIRED_WORKLOAD_CLASSES {
            let _ = service
                .create_perf_attestation(
                    CreatePerfAttestationRequest {
                        instance_id: instance.to_string(),
                        workload_class: workload_class.to_string(),
                        claim_tier: None,
                        claim_evidence_mode: None,
                        cpu_overhead_pct: 4,
                        memory_overhead_pct: 4,
                        block_io_latency_overhead_pct: 8,
                        network_latency_overhead_pct: 8,
                        jitter_pct: 7,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let summary = service
            .observe_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            summary["perf_attestation_count"].as_u64(),
            Some(REQUIRED_WORKLOAD_CLASSES.len() as u64)
        );
        assert_eq!(summary["failure_report_count"].as_u64(), Some(0));
        assert_eq!(summary["service"].as_str(), Some("uvm-observe"));
        assert_eq!(
            summary["native_claim_status"]["native_indistinguishable_status"].as_bool(),
            Some(true)
        );
    }

    #[tokio::test]
    async fn evidence_summary_route_reports_evidence_rollup() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let runtime_preflight_id = persist_runtime_preflight_artifact_source(
            temp.path(),
            "linux",
            "linux_bare_metal",
            Some("measured"),
            Some("kvm"),
        )
        .await;
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_perf_attestation(
                CreatePerfAttestationRequest {
                    instance_id: instance.to_string(),
                    workload_class: String::from("general"),
                    claim_tier: Some(String::from("compatible")),
                    claim_evidence_mode: Some(String::from("measured")),
                    cpu_overhead_pct: 5,
                    memory_overhead_pct: 5,
                    block_io_latency_overhead_pct: 5,
                    network_latency_overhead_pct: 5,
                    jitter_pct: 5,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let host_evidence = service
            .create_host_evidence(
                CreateHostEvidenceRequest {
                    evidence_mode: String::from("measured"),
                    host_platform: String::from("linux"),
                    execution_environment: String::from("bare_metal"),
                    hardware_virtualization: true,
                    nested_virtualization: true,
                    qemu_available: true,
                    note: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let host_evidence: UvmHostEvidenceRecord = response_json(host_evidence).await;

        let _ = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let campaign = service
            .create_benchmark_campaign(
                CreateBenchmarkCampaignRequest {
                    name: String::from("summary-campaign"),
                    target: String::from("host"),
                    workload_class: String::from("general"),
                    require_qemu_baseline: Some(true),
                    require_container_baseline: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let campaign: UvmBenchmarkCampaignRecord = response_json(campaign).await;

        let result = service
            .create_benchmark_result(
                CreateBenchmarkResultRequest {
                    campaign_id: campaign.id.to_string(),
                    engine: String::from("software_dbt"),
                    scenario: String::from("service_readiness"),
                    guest_run_lineage: None,
                    measurement_mode: Some(String::from("direct")),
                    evidence_mode: String::from("measured"),
                    measured: true,
                    boot_time_ms: 123,
                    steady_state_score: 999,
                    control_plane_p99_ms: 10,
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    note: Some(String::from("summary")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let result: UvmBenchmarkResultRecord = response_json(result).await;

        let summary = service
            .evidence_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(summary["perf_attestation_count"].as_u64(), Some(1));
        assert_eq!(summary["host_evidence_count"].as_u64(), Some(1));
        assert_eq!(summary["claim_decision_count"].as_u64(), Some(1));
        assert_eq!(
            summary["preflight_evidence_artifact_count"].as_u64(),
            Some(1)
        );
        assert_eq!(summary["benchmark_result_count"].as_u64(), Some(1));
        assert_eq!(
            summary["latest_benchmark_result"]["engine"].as_str(),
            Some(result.engine.as_str())
        );
        assert_eq!(
            summary["latest_benchmark_result"]["scenario"].as_str(),
            Some(result.scenario.as_str())
        );
        assert_eq!(
            summary["latest_benchmark_result"]["measurement_mode"].as_str(),
            Some("direct")
        );
        assert_eq!(
            summary["latest_preflight_evidence_artifact"]["runtime_preflight_id"].as_str(),
            Some(runtime_preflight_id.as_str())
        );
        assert_eq!(
            summary["latest_preflight_evidence_artifact"]["host_class_evidence_key"].as_str(),
            Some("linux_bare_metal")
        );
        assert_eq!(
            summary["latest_preflight_evidence_artifact"]["selected_backend"].as_str(),
            Some("kvm")
        );
    }

    #[tokio::test]
    async fn host_evidence_and_claim_decision_drive_claim_status() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        create_strong_perf_samples(&service, &instance, &context).await;

        let host_evidence = service
            .create_host_evidence(
                CreateHostEvidenceRequest {
                    evidence_mode: String::from("measured"),
                    host_platform: String::from("linux"),
                    execution_environment: String::from("bare_metal"),
                    hardware_virtualization: true,
                    nested_virtualization: true,
                    qemu_available: true,
                    note: Some(String::from("bench host")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let host_evidence: UvmHostEvidenceRecord = response_json(host_evidence).await;

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;
        assert_eq!(decision.claim_status, "allowed");
        assert_eq!(decision.highest_claim_tier, "compatible");
        assert_eq!(decision.observed_highest_claim_tier, "competitive");
        assert_eq!(decision.benchmark_claim_tier_ceiling, "compatible");
        assert!(decision.benchmark_ready_scenarios.is_empty());
        assert_eq!(decision.prohibited_claim_count, 0);
        assert!(decision.runtime_session_id.is_none());
        assert!(decision.portability_assessment.is_none());
        assert_eq!(
            decision.portability_assessment_source,
            UvmPortabilityAssessmentSource::Unavailable
        );
        assert_eq!(
            decision
                .metadata
                .annotations
                .get("observed_highest_claim_tier")
                .map(String::as_str),
            Some("competitive")
        );
        assert_eq!(
            decision
                .metadata
                .annotations
                .get("benchmark_claim_tier_ceiling")
                .map(String::as_str),
            Some("compatible")
        );
        assert_eq!(
            decision
                .metadata
                .annotations
                .get("claim_tier_demoted_from")
                .map(String::as_str),
            Some("competitive")
        );

        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status["claim_status"].as_str(), Some("allowed"));
        assert_eq!(
            status["observed_highest_claim_tier"].as_str(),
            Some("competitive")
        );
        assert_eq!(status["highest_claim_tier"].as_str(), Some("compatible"));
        assert_eq!(
            status["benchmark_claim_tier_ceiling"].as_str(),
            Some("compatible")
        );
        assert_eq!(
            status["benchmark_ready_scenarios"].as_array().map(Vec::len),
            Some(0)
        );
        assert_eq!(
            status["host_evidence_id"].as_str(),
            Some(host_evidence.id.as_str())
        );
        assert!(status["runtime_session_id"].is_null());
    }

    #[tokio::test]
    async fn direct_benchmark_sufficiency_preserves_competitive_claim_tier() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        create_strong_perf_samples(&service, &instance, &context).await;
        let host_evidence = create_measured_host_evidence(&service, &context).await;
        for &workload_class in REQUIRED_WORKLOAD_CLASSES {
            create_direct_benchmark_claim_proof(
                &service,
                &context,
                &host_evidence,
                workload_class,
                &["steady_state"],
            )
            .await;
        }

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;
        assert_eq!(decision.claim_status, "allowed");
        assert_eq!(decision.highest_claim_tier, "competitive");
        assert_eq!(decision.observed_highest_claim_tier, "competitive");
        assert_eq!(decision.benchmark_claim_tier_ceiling, "competitive");
        assert_eq!(
            decision.benchmark_ready_scenarios,
            vec![String::from("steady_state")]
        );
        assert_eq!(
            decision
                .metadata
                .annotations
                .get("observed_highest_claim_tier")
                .map(String::as_str),
            Some("competitive")
        );
        assert_eq!(
            decision
                .metadata
                .annotations
                .get("benchmark_claim_tier_ceiling")
                .map(String::as_str),
            Some("competitive")
        );
        assert!(
            !decision
                .metadata
                .annotations
                .contains_key("claim_tier_demoted_from")
        );

        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status["claim_status"].as_str(), Some("allowed"));
        assert_eq!(
            status["observed_highest_claim_tier"].as_str(),
            Some("competitive")
        );
        assert_eq!(status["highest_claim_tier"].as_str(), Some("competitive"));
        assert_eq!(
            status["benchmark_claim_tier_ceiling"].as_str(),
            Some("competitive")
        );
        assert!(
            status["benchmark_ready_scenarios"]
                .as_array()
                .unwrap_or(&Vec::new())
                .iter()
                .filter_map(|value| value.as_str())
                .any(|value| value == "steady_state")
        );
    }

    #[tokio::test]
    async fn steady_state_only_proof_demotes_faster_boot_path_to_competitive() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        create_perf_samples_with_claim_tier(
            &service,
            &instance,
            &context,
            "faster_boot_path",
            "measured",
        )
        .await;
        let host_evidence = create_measured_host_evidence(&service, &context).await;
        for &workload_class in REQUIRED_WORKLOAD_CLASSES {
            create_direct_benchmark_claim_proof(
                &service,
                &context,
                &host_evidence,
                workload_class,
                &["steady_state"],
            )
            .await;
        }

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;
        assert_eq!(decision.claim_status, "allowed");
        assert_eq!(decision.highest_claim_tier, "competitive");
        assert_eq!(decision.observed_highest_claim_tier, "faster_boot_path");
        assert_eq!(decision.benchmark_claim_tier_ceiling, "competitive");
        assert_eq!(
            decision
                .metadata
                .annotations
                .get("observed_highest_claim_tier")
                .map(String::as_str),
            Some("faster_boot_path")
        );
        assert_eq!(
            decision
                .metadata
                .annotations
                .get("claim_tier_demoted_from")
                .map(String::as_str),
            Some("faster_boot_path")
        );
    }

    #[tokio::test]
    async fn claim_decision_reopen_backfills_top_level_tier_fields_from_annotations() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        create_strong_perf_samples(&service, &instance, &context).await;
        let host_evidence = create_measured_host_evidence(&service, &context).await;

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;
        drop(service);

        let claim_decisions_path = temp.path().join("uvm-observe/claim_decisions.json");
        let mut raw: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&claim_decisions_path).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        for record in raw["records"]
            .as_object_mut()
            .unwrap_or_else(|| panic!("missing claim decision records"))
            .values_mut()
        {
            let value = record["value"]
                .as_object_mut()
                .unwrap_or_else(|| panic!("missing claim decision record value"));
            value.remove("observed_highest_claim_tier");
            value.remove("benchmark_claim_tier_ceiling");
        }
        for change in raw["changes"]
            .as_array_mut()
            .unwrap_or_else(|| panic!("missing claim decision changes"))
        {
            let value = change["document"]["value"]
                .as_object_mut()
                .unwrap_or_else(|| panic!("missing claim decision change value"));
            value.remove("observed_highest_claim_tier");
            value.remove("benchmark_claim_tier_ceiling");
        }
        std::fs::write(
            &claim_decisions_path,
            serde_json::to_vec_pretty(&raw).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let reopened = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let claim_decisions = reopened
            .list_claim_decisions()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(claim_decisions.len(), 1);
        assert_eq!(claim_decisions[0].id, decision.id);
        assert_eq!(
            claim_decisions[0].observed_highest_claim_tier,
            "competitive"
        );
        assert_eq!(
            claim_decisions[0].benchmark_claim_tier_ceiling,
            "compatible"
        );

        let rewritten: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&claim_decisions_path).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let rewritten_record = rewritten["records"][decision.id.as_str()]["value"]
            .as_object()
            .unwrap_or_else(|| panic!("missing rewritten claim decision value"));
        assert_eq!(
            rewritten_record
                .get("observed_highest_claim_tier")
                .and_then(serde_json::Value::as_str),
            Some("competitive")
        );
        assert_eq!(
            rewritten_record
                .get("benchmark_claim_tier_ceiling")
                .and_then(serde_json::Value::as_str),
            Some("compatible")
        );
    }

    #[tokio::test]
    async fn claim_decision_reopen_backfills_top_level_benchmark_ready_scenarios_from_annotations()
    {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        create_strong_perf_samples(&service, &instance, &context).await;
        let host_evidence = create_measured_host_evidence(&service, &context).await;
        for &workload_class in REQUIRED_WORKLOAD_CLASSES {
            create_direct_benchmark_claim_proof(
                &service,
                &context,
                &host_evidence,
                workload_class,
                &["steady_state"],
            )
            .await;
        }

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;
        drop(service);

        let claim_decisions_path = temp.path().join("uvm-observe/claim_decisions.json");
        let mut raw: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&claim_decisions_path).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        for record in raw["records"]
            .as_object_mut()
            .unwrap_or_else(|| panic!("missing claim decision records"))
            .values_mut()
        {
            let value = record["value"]
                .as_object_mut()
                .unwrap_or_else(|| panic!("missing claim decision record value"));
            value.remove("benchmark_ready_scenarios");
        }
        for change in raw["changes"]
            .as_array_mut()
            .unwrap_or_else(|| panic!("missing claim decision changes"))
        {
            let value = change["document"]["value"]
                .as_object_mut()
                .unwrap_or_else(|| panic!("missing claim decision change value"));
            value.remove("benchmark_ready_scenarios");
        }
        std::fs::write(
            &claim_decisions_path,
            serde_json::to_vec_pretty(&raw).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let reopened = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let claim_decisions = reopened
            .list_claim_decisions()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(claim_decisions.len(), 1);
        assert_eq!(claim_decisions[0].id, decision.id);
        assert_eq!(
            claim_decisions[0].benchmark_ready_scenarios,
            vec![String::from("steady_state")]
        );

        let rewritten: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&claim_decisions_path).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let rewritten_record = rewritten["records"][decision.id.as_str()]["value"]
            .as_object()
            .unwrap_or_else(|| panic!("missing rewritten claim decision value"));
        assert_eq!(
            rewritten_record
                .get("benchmark_ready_scenarios")
                .and_then(serde_json::Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>()
                }),
            Some(vec!["steady_state"])
        );
    }

    #[tokio::test]
    async fn claim_decision_with_scoped_image_artifact_surfaces_and_backfills_structured_publication_scope()
     {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let scoped_portability = supported_portability_with_scoped_image_artifact(
            "linux_bare_metal",
            "competitive",
            "kvm",
        );
        let _runtime_session_id =
            persist_runtime_session_intent_lineage_with_first_placement_portability(
                temp.path(),
                &instance,
                Some(scoped_portability.clone()),
                None,
            )
            .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;

        let proof_host = create_measured_host_evidence(&service, &context).await;
        create_direct_benchmark_claim_proof(
            &service,
            &context,
            &proof_host,
            "general",
            &["steady_state"],
        )
        .await;

        let latest_host =
            create_measured_host_evidence_for_environment(&service, &context, "hosted_ci").await;

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(latest_host.id.to_string()),
                    runtime_preflight_id: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;
        assert_eq!(
            decision
                .metadata
                .annotations
                .get("publication_scope_host_class_evidence_key")
                .map(String::as_str),
            Some("linux_bare_metal")
        );
        assert_eq!(
            decision
                .metadata
                .annotations
                .get("publication_scope_region")
                .map(String::as_str),
            Some("global")
        );
        assert_eq!(
            decision
                .metadata
                .annotations
                .get("publication_scope_cell")
                .map(String::as_str),
            Some("global")
        );
        assert_eq!(
            decision
                .metadata
                .annotations
                .get("publication_scope_backend")
                .map(String::as_str),
            Some("kvm")
        );

        let claim_decided = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|message| message.topic == "uvm.observe.claim_decided.v1")
            .unwrap_or_else(|| panic!("missing claim-decided outbox message"));
        let details = match &claim_decided.payload.payload {
            EventPayload::Service(event) => {
                assert_eq!(event.resource_id, decision.id.as_str());
                &event.details
            }
            other => panic!("unexpected outbox payload kind: {other:?}"),
        };
        assert_eq!(
            details["publication_scope_host_class_evidence_key"].as_str(),
            Some("linux_bare_metal")
        );
        assert_eq!(details["publication_scope_region"].as_str(), Some("global"));
        assert_eq!(details["publication_scope_cell"].as_str(), Some("global"));
        assert_eq!(details["publication_scope_backend"].as_str(), Some("kvm"));

        drop(service);

        let claim_decisions_path = temp.path().join("uvm-observe/claim_decisions.json");
        let mut raw: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&claim_decisions_path).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let annotations = raw["records"][decision.id.as_str()]["value"]["metadata"]["annotations"]
            .as_object_mut()
            .unwrap_or_else(|| panic!("missing persisted claim decision annotations"));
        annotations.remove("publication_scope_region");
        annotations.remove("publication_scope_cell");
        annotations.remove("publication_scope_backend");
        std::fs::write(
            &claim_decisions_path,
            serde_json::to_vec_pretty(&raw).unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let reopened = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let claim_decisions = reopened
            .list_claim_decisions()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(claim_decisions.len(), 1);
        assert_eq!(
            claim_decisions[0]
                .metadata
                .annotations
                .get("publication_scope_region")
                .map(String::as_str),
            Some("global")
        );
        assert_eq!(
            claim_decisions[0]
                .metadata
                .annotations
                .get("publication_scope_cell")
                .map(String::as_str),
            Some("global")
        );
        assert_eq!(
            claim_decisions[0]
                .metadata
                .annotations
                .get("publication_scope_backend")
                .map(String::as_str),
            Some("kvm")
        );
    }

    #[tokio::test]
    async fn claim_decision_persists_portability_assessment_and_demotes_unsupported_claims() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        for &workload_class in REQUIRED_WORKLOAD_CLASSES {
            let _ = service
                .create_perf_attestation(
                    CreatePerfAttestationRequest {
                        instance_id: instance.to_string(),
                        workload_class: workload_class.to_string(),
                        claim_tier: Some(String::from("competitive")),
                        claim_evidence_mode: Some(String::from("measured")),
                        cpu_overhead_pct: 4,
                        memory_overhead_pct: 4,
                        block_io_latency_overhead_pct: 8,
                        network_latency_overhead_pct: 8,
                        jitter_pct: 7,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let host_evidence = service
            .create_host_evidence(
                CreateHostEvidenceRequest {
                    evidence_mode: String::from("measured"),
                    host_platform: String::from("linux"),
                    execution_environment: String::from("bare_metal"),
                    hardware_virtualization: true,
                    nested_virtualization: true,
                    qemu_available: true,
                    note: Some(String::from("benchmark host")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let host_evidence: UvmHostEvidenceRecord = response_json(host_evidence).await;

        let portability_assessment = UvmPortabilityAssessment {
            intent: UvmExecutionIntent {
                preferred_backend: Some(HypervisorBackend::Kvm),
                fallback_policy: UvmBackendFallbackPolicy::RequirePreferred,
                required_portability_tier: UvmPortabilityTier::Portable,
                evidence_strictness: UvmEvidenceStrictness::AllowSimulated,
            },
            supported: false,
            eligible_backends: vec![HypervisorBackend::SoftwareDbt],
            selected_backend: None,
            selected_via_fallback: false,
            selection_reason: None,
            blockers: vec![String::from(
                "preferred backend kvm is not eligible on host linux for guest_architecture x86_64",
            )],
            evidence: vec![
                UvmCompatibilityEvidence {
                    source: UvmCompatibilityEvidenceSource::ExecutionIntent,
                    summary: String::from(
                        "preferred_backend=kvm fallback_policy=require_preferred required_portability_tier=portable evidence_strictness=allow_simulated",
                    ),
                    evidence_mode: Some(String::from("measured")),
                },
                UvmCompatibilityEvidence {
                    source: UvmCompatibilityEvidenceSource::RuntimePreflight,
                    summary: String::from("eligible_backends=software_dbt"),
                    evidence_mode: None,
                },
            ],
        };

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: None,
                    portability_assessment: Some(portability_assessment.clone()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;

        assert_eq!(decision.claim_status, "restricted");
        assert_eq!(
            decision.portability_assessment,
            Some(portability_assessment.clone())
        );
        assert_eq!(
            decision.portability_assessment_source,
            UvmPortabilityAssessmentSource::RequestFallback
        );

        let decisions = service
            .list_claim_decisions()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(decisions.len(), 1);
        assert_eq!(
            decisions[0].portability_assessment,
            Some(portability_assessment)
        );
        assert_eq!(
            decisions[0].portability_assessment_source,
            UvmPortabilityAssessmentSource::RequestFallback
        );
    }

    #[tokio::test]
    async fn claim_decision_auto_ingests_runtime_preflight_assessment_and_prefers_node_evidence() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let default_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt, HypervisorBackend::Kvm],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            None,
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(default_portability.supported);
        assert_eq!(default_portability.intent, UvmExecutionIntent::default());
        let runtime_preflight_id = persist_runtime_preflight_portability_assessment(
            temp.path(),
            Some(default_portability.clone()),
        )
        .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let host_evidence = create_measured_host_evidence(&service, &context).await;

        let request_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            Some(&UvmExecutionIntent {
                preferred_backend: Some(HypervisorBackend::Kvm),
                fallback_policy: UvmBackendFallbackPolicy::RequirePreferred,
                required_portability_tier: UvmPortabilityTier::Portable,
                evidence_strictness: UvmEvidenceStrictness::AllowSimulated,
            }),
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!request_portability.supported);

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: Some(runtime_preflight_id.to_string()),
                    portability_assessment: Some(request_portability),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;

        assert_eq!(decision.claim_status, "allowed");
        assert_eq!(
            decision.runtime_preflight_id,
            Some(runtime_preflight_id.clone())
        );
        assert_eq!(
            decision.portability_assessment,
            Some(default_portability.clone())
        );
        assert_eq!(
            decision.portability_assessment_source,
            UvmPortabilityAssessmentSource::RuntimePreflightFallback
        );
        assert_eq!(
            decision
                .portability_assessment
                .as_ref()
                .unwrap_or_else(|| panic!("missing portability assessment"))
                .intent,
            UvmExecutionIntent::default()
        );

        let decisions = service
            .list_claim_decisions()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(decisions.len(), 1);
        assert_eq!(
            decisions[0].runtime_preflight_id,
            Some(runtime_preflight_id)
        );
        assert_eq!(
            decisions[0].portability_assessment,
            Some(default_portability)
        );
        assert_eq!(
            decisions[0].portability_assessment_source,
            UvmPortabilityAssessmentSource::RuntimePreflightFallback
        );
    }

    #[tokio::test]
    async fn claim_decision_auto_ingests_unsupported_runtime_preflight_assessment() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let unsupported_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::Kvm],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: true,
                require_secure_boot: true,
            },
            Some(&UvmExecutionIntent {
                preferred_backend: Some(HypervisorBackend::HypervWhp),
                fallback_policy: UvmBackendFallbackPolicy::RequirePreferred,
                required_portability_tier: UvmPortabilityTier::Portable,
                evidence_strictness: UvmEvidenceStrictness::AllowSimulated,
            }),
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!unsupported_portability.supported);
        let runtime_preflight_id = persist_runtime_preflight_portability_assessment(
            temp.path(),
            Some(unsupported_portability.clone()),
        )
        .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let host_evidence = create_measured_host_evidence(&service, &context).await;

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: Some(runtime_preflight_id.to_string()),
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;

        assert_eq!(decision.claim_status, "restricted");
        assert_eq!(decision.runtime_preflight_id, Some(runtime_preflight_id));
        assert_eq!(
            decision.portability_assessment,
            Some(unsupported_portability.clone())
        );
        assert_eq!(
            decision.portability_assessment_source,
            UvmPortabilityAssessmentSource::RuntimePreflightFallback
        );
        assert!(
            decision
                .portability_assessment
                .as_ref()
                .unwrap_or_else(|| panic!("missing portability assessment"))
                .blockers
                .iter()
                .any(|value| value.contains("preferred backend hyperv_whp"))
        );
    }

    #[tokio::test]
    async fn claim_decision_retains_request_fallback_when_runtime_preflight_has_no_assessment() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let runtime_preflight_id =
            persist_runtime_preflight_portability_assessment(temp.path(), None).await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let host_evidence = create_measured_host_evidence(&service, &context).await;

        let request_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            Some(&UvmExecutionIntent {
                preferred_backend: Some(HypervisorBackend::Kvm),
                fallback_policy: UvmBackendFallbackPolicy::AllowCompatible,
                required_portability_tier: UvmPortabilityTier::Portable,
                evidence_strictness: UvmEvidenceStrictness::AllowSimulated,
            }),
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(request_portability.supported);

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: Some(runtime_preflight_id.to_string()),
                    portability_assessment: Some(request_portability.clone()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;

        assert_eq!(decision.claim_status, "allowed");
        assert!(decision.runtime_session_id.is_none());
        assert_eq!(
            decision.runtime_preflight_id,
            Some(runtime_preflight_id.clone())
        );
        assert_eq!(
            decision.portability_assessment,
            Some(request_portability.clone())
        );
        assert_eq!(
            decision.portability_assessment_source,
            UvmPortabilityAssessmentSource::RequestFallback
        );
    }

    #[tokio::test]
    async fn claim_decision_reports_linked_runtime_preflight_lineage_when_session_link_wins() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let supported_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt, HypervisorBackend::Kvm],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            None,
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let runtime_preflight_id = persist_runtime_preflight_portability_assessment(
            temp.path(),
            Some(supported_portability.clone()),
        )
        .await;
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id = persist_runtime_session_intent_lineage(
            temp.path(),
            &instance,
            Some(runtime_preflight_id.clone()),
        )
        .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let host_evidence = create_measured_host_evidence(&service, &context).await;

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: Some(runtime_preflight_id.to_string()),
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;

        assert_eq!(decision.claim_status, "allowed");
        assert_eq!(decision.runtime_session_id, Some(runtime_session_id));
        assert_eq!(decision.runtime_preflight_id, Some(runtime_preflight_id));
        assert_eq!(decision.portability_assessment, Some(supported_portability));
        assert_eq!(
            decision.portability_assessment_source,
            UvmPortabilityAssessmentSource::LinkedRuntimePreflightLineage
        );
    }

    #[tokio::test]
    async fn claim_decision_prefers_first_placement_lineage_over_request_portability_inputs() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let supported_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt, HypervisorBackend::Kvm],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            None,
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let unsupported_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            Some(&UvmExecutionIntent {
                preferred_backend: Some(HypervisorBackend::Kvm),
                fallback_policy: UvmBackendFallbackPolicy::RequirePreferred,
                required_portability_tier: UvmPortabilityTier::Portable,
                evidence_strictness: UvmEvidenceStrictness::AllowSimulated,
            }),
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!unsupported_portability.supported);
        let runtime_preflight_id = persist_runtime_preflight_portability_assessment(
            temp.path(),
            Some(unsupported_portability.clone()),
        )
        .await;
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id =
            persist_runtime_session_intent_lineage_with_first_placement_portability(
                temp.path(),
                &instance,
                Some(supported_portability.clone()),
                Some(runtime_preflight_id.clone()),
            )
            .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let host_evidence = create_measured_host_evidence(&service, &context).await;

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: Some(runtime_preflight_id.to_string()),
                    portability_assessment: Some(unsupported_portability),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;

        assert_eq!(decision.claim_status, "allowed");
        assert_eq!(decision.runtime_session_id, Some(runtime_session_id));
        assert_eq!(decision.runtime_preflight_id, Some(runtime_preflight_id));
        assert_eq!(
            decision.portability_assessment,
            Some(supported_portability.clone())
        );
        assert_eq!(
            decision.portability_assessment_source,
            UvmPortabilityAssessmentSource::FirstPlacementLineage
        );
        assert_eq!(
            decision
                .portability_assessment
                .as_ref()
                .unwrap_or_else(|| panic!("missing portability assessment"))
                .intent,
            UvmExecutionIntent::default()
        );
    }

    #[tokio::test]
    async fn claim_decision_auto_derives_default_portability_from_single_runtime_lineage() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let default_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt, HypervisorBackend::Kvm],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            None,
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id =
            persist_runtime_session_intent_lineage_with_first_placement_portability(
                temp.path(),
                &instance,
                Some(default_portability.clone()),
                None,
            )
            .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let host_evidence = create_measured_host_evidence(&service, &context).await;

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;

        assert_eq!(decision.claim_status, "allowed");
        assert_eq!(decision.runtime_session_id, Some(runtime_session_id));
        assert_eq!(decision.runtime_preflight_id, None);
        assert_eq!(
            decision.portability_assessment,
            Some(default_portability.clone())
        );
        assert_eq!(
            decision
                .portability_assessment
                .as_ref()
                .unwrap_or_else(|| panic!("missing portability assessment"))
                .intent,
            UvmExecutionIntent::default()
        );
    }

    #[tokio::test]
    async fn claim_decision_surfaces_authoritative_runtime_session_when_portability_lineage_is_unavailable()
     {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id =
            persist_runtime_session_intent_lineage(temp.path(), &instance, None).await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let host_evidence = create_measured_host_evidence(&service, &context).await;

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;

        assert_eq!(decision.claim_status, "allowed");
        assert_eq!(decision.runtime_session_id, Some(runtime_session_id));
        assert_eq!(decision.runtime_preflight_id, None);
        assert!(decision.portability_assessment.is_none());
        assert_eq!(
            decision.portability_assessment_source,
            UvmPortabilityAssessmentSource::Unavailable
        );
        assert_eq!(
            decision.portability_assessment_unavailable_reason,
            Some(
                UvmPortabilityAssessmentUnavailableReason::AuthoritativeRuntimeLineageMissingPortabilityEvidence,
            )
        );
    }

    #[tokio::test]
    async fn claim_decision_surfaces_authoritative_preflight_link_when_portability_is_unavailable()
    {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime_preflight_id =
            persist_runtime_preflight_portability_assessment(temp.path(), None).await;
        let runtime_session_id = persist_runtime_session_intent_lineage(
            temp.path(),
            &instance,
            Some(runtime_preflight_id.clone()),
        )
        .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let host_evidence = create_measured_host_evidence(&service, &context).await;

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;

        assert_eq!(decision.claim_status, "allowed");
        assert_eq!(decision.runtime_session_id, Some(runtime_session_id));
        assert_eq!(decision.runtime_preflight_id, Some(runtime_preflight_id));
        assert!(decision.portability_assessment.is_none());
        assert_eq!(
            decision.portability_assessment_source,
            UvmPortabilityAssessmentSource::Unavailable
        );
        assert_eq!(
            decision.portability_assessment_unavailable_reason,
            Some(
                UvmPortabilityAssessmentUnavailableReason::AuthoritativeRuntimeLineageMissingPortabilityEvidence,
            )
        );
    }

    #[tokio::test]
    async fn claim_decision_does_not_resurrect_stale_runtime_preflight_link_when_authoritative_lineage_is_missing()
     {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let stale_runtime_preflight_id =
            persist_runtime_preflight_portability_assessment(temp.path(), None).await;
        let stale_runtime_session_id = persist_runtime_session_intent_lineage(
            temp.path(),
            &instance,
            Some(stale_runtime_preflight_id),
        )
        .await;
        soft_delete_runtime_session_presence(temp.path(), &stale_runtime_session_id).await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let host_evidence = create_measured_host_evidence(&service, &context).await;

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: None,
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;

        assert_eq!(decision.claim_status, "allowed");
        assert!(decision.runtime_session_id.is_none());
        assert!(decision.runtime_preflight_id.is_none());
        assert!(decision.portability_assessment.is_none());
        assert_eq!(
            decision.portability_assessment_source,
            UvmPortabilityAssessmentSource::Unavailable
        );
        assert!(decision.portability_assessment_unavailable_reason.is_none());
    }

    #[tokio::test]
    async fn claim_decision_surfaces_unsupported_first_placement_lineage_over_supported_preflight()
    {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let supported_preflight_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt, HypervisorBackend::Kvm],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            None,
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let unsupported_first_placement = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            Some(&UvmExecutionIntent {
                preferred_backend: Some(HypervisorBackend::Kvm),
                fallback_policy: UvmBackendFallbackPolicy::RequirePreferred,
                required_portability_tier: UvmPortabilityTier::Portable,
                evidence_strictness: UvmEvidenceStrictness::AllowSimulated,
            }),
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!unsupported_first_placement.supported);
        let runtime_preflight_id = persist_runtime_preflight_portability_assessment(
            temp.path(),
            Some(supported_preflight_portability),
        )
        .await;
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id =
            persist_runtime_session_intent_lineage_with_first_placement_portability(
                temp.path(),
                &instance,
                Some(unsupported_first_placement.clone()),
                Some(runtime_preflight_id.clone()),
            )
            .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let host_evidence = create_measured_host_evidence(&service, &context).await;

        let decision = service
            .create_claim_decision(
                CreateClaimDecisionRequest {
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    runtime_preflight_id: Some(runtime_preflight_id.to_string()),
                    portability_assessment: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let decision: UvmClaimDecisionRecord = response_json(decision).await;

        assert_eq!(decision.claim_status, "restricted");
        assert_eq!(decision.runtime_session_id, Some(runtime_session_id));
        assert_eq!(decision.runtime_preflight_id, Some(runtime_preflight_id));
        assert_eq!(
            decision.portability_assessment,
            Some(unsupported_first_placement.clone())
        );
        assert!(
            decision
                .portability_assessment
                .as_ref()
                .unwrap_or_else(|| panic!("missing portability assessment"))
                .blockers
                .iter()
                .any(|value| value.contains("preferred backend kvm"))
        );
    }

    #[tokio::test]
    async fn native_claim_status_prefers_first_placement_portability_before_migration_preflight() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let supported_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt, HypervisorBackend::Kvm],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            None,
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id =
            persist_runtime_session_intent_lineage_with_first_placement_portability(
                temp.path(),
                &instance,
                Some(supported_portability.clone()),
                None,
            )
            .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let _host_evidence = create_measured_host_evidence(&service, &context).await;

        let latest_perf_samples = UvmObserveService::latest_perf_samples(
            service
                .active_perf_attestations()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let resolved = service
            .resolve_runtime_lineage_portability_assessments(&latest_perf_samples)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].instance_id, instance);
        assert_eq!(resolved[0].runtime_session_id, runtime_session_id);
        assert_eq!(resolved[0].runtime_preflight_id, None);
        assert_eq!(resolved[0].portability_assessment, supported_portability);

        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status["claim_status"].as_str(), Some("allowed"));
        assert_native_claim_status_portability(
            &status,
            Some(&supported_portability),
            UvmPortabilityAssessmentSource::FirstPlacementLineage,
            Some(&runtime_session_id),
            None,
            None,
        );
    }

    #[tokio::test]
    async fn native_claim_status_uses_scoped_image_artifact_for_benchmark_proof_scope() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let scoped_portability = supported_portability_with_scoped_image_artifact(
            "linux_bare_metal",
            "competitive",
            "kvm",
        );
        let runtime_session_id =
            persist_runtime_session_intent_lineage_with_first_placement_portability(
                temp.path(),
                &instance,
                Some(scoped_portability.clone()),
                None,
            )
            .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;

        let proof_host = create_measured_host_evidence(&service, &context).await;
        create_direct_benchmark_claim_proof(
            &service,
            &context,
            &proof_host,
            "general",
            &["steady_state"],
        )
        .await;

        let _latest_host =
            create_measured_host_evidence_for_environment(&service, &context, "hosted_ci").await;

        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            status["host_class_evidence_key"].as_str(),
            Some("linux_hosted_ci")
        );
        assert_eq!(
            status["publication_scope_host_class_evidence_key"].as_str(),
            Some("linux_bare_metal")
        );
        assert_eq!(status["publication_scope_region"].as_str(), Some("global"));
        assert_eq!(status["publication_scope_cell"].as_str(), Some("global"));
        assert_eq!(status["publication_scope_backend"].as_str(), Some("kvm"));
        assert_eq!(status["highest_claim_tier"].as_str(), Some("competitive"));
        assert_eq!(status["claim_status"].as_str(), Some("allowed"));
        assert_native_claim_status_portability(
            &status,
            Some(&scoped_portability),
            UvmPortabilityAssessmentSource::FirstPlacementLineage,
            Some(&runtime_session_id),
            None,
            None,
        );
    }

    #[tokio::test]
    async fn native_claim_status_prefers_first_placement_portability_over_runtime_preflight_link() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let supported_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt, HypervisorBackend::Kvm],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            None,
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let unsupported_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            Some(&UvmExecutionIntent {
                preferred_backend: Some(HypervisorBackend::Kvm),
                fallback_policy: UvmBackendFallbackPolicy::RequirePreferred,
                required_portability_tier: UvmPortabilityTier::Portable,
                evidence_strictness: UvmEvidenceStrictness::AllowSimulated,
            }),
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!unsupported_portability.supported);
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime_preflight_id = persist_runtime_preflight_portability_assessment(
            temp.path(),
            Some(unsupported_portability),
        )
        .await;
        let runtime_session_id =
            persist_runtime_session_intent_lineage_with_first_placement_portability(
                temp.path(),
                &instance,
                Some(supported_portability.clone()),
                Some(runtime_preflight_id.clone()),
            )
            .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let _host_evidence = create_measured_host_evidence(&service, &context).await;

        let latest_perf_samples = UvmObserveService::latest_perf_samples(
            service
                .active_perf_attestations()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let resolved = service
            .resolve_runtime_lineage_portability_assessments(&latest_perf_samples)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].instance_id, instance);
        assert_eq!(resolved[0].runtime_session_id, runtime_session_id);
        assert_eq!(resolved[0].runtime_preflight_id, None);
        assert_eq!(resolved[0].portability_assessment, supported_portability);

        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status["claim_status"].as_str(), Some("allowed"));
        assert_native_claim_status_portability(
            &status,
            Some(&supported_portability),
            UvmPortabilityAssessmentSource::FirstPlacementLineage,
            Some(&runtime_session_id),
            None,
            None,
        );
    }

    #[tokio::test]
    async fn native_claim_status_restricts_claims_when_first_placement_portability_is_unsupported()
    {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let unsupported_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            Some(&UvmExecutionIntent {
                preferred_backend: Some(HypervisorBackend::Kvm),
                fallback_policy: UvmBackendFallbackPolicy::RequirePreferred,
                required_portability_tier: UvmPortabilityTier::Portable,
                evidence_strictness: UvmEvidenceStrictness::AllowSimulated,
            }),
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!unsupported_portability.supported);
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id =
            persist_runtime_session_intent_lineage_with_first_placement_portability(
                temp.path(),
                &instance,
                Some(unsupported_portability.clone()),
                None,
            )
            .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let _host_evidence = create_measured_host_evidence(&service, &context).await;

        let latest_perf_samples = UvmObserveService::latest_perf_samples(
            service
                .active_perf_attestations()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let resolved = service
            .resolve_runtime_lineage_portability_assessments(&latest_perf_samples)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].instance_id, instance);
        assert_eq!(resolved[0].runtime_session_id, runtime_session_id);
        assert_eq!(resolved[0].runtime_preflight_id, None);
        assert!(
            resolved[0]
                .portability_assessment
                .blockers
                .iter()
                .any(|value| value.contains("preferred backend kvm"))
        );

        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status["claim_status"].as_str(), Some("restricted"));
        assert_native_claim_status_portability(
            &status,
            Some(&unsupported_portability),
            UvmPortabilityAssessmentSource::FirstPlacementLineage,
            Some(&runtime_session_id),
            None,
            None,
        );
    }

    #[tokio::test]
    async fn native_claim_status_resolves_supported_portability_from_runtime_session_lineage() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let supported_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt, HypervisorBackend::Kvm],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            None,
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime_preflight_id = persist_runtime_preflight_portability_assessment(
            temp.path(),
            Some(supported_portability.clone()),
        )
        .await;
        let runtime_session_id = persist_runtime_session_intent_lineage(
            temp.path(),
            &instance,
            Some(runtime_preflight_id.clone()),
        )
        .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let _host_evidence = create_measured_host_evidence(&service, &context).await;

        let latest_perf_samples = UvmObserveService::latest_perf_samples(
            service
                .active_perf_attestations()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let resolved = service
            .resolve_runtime_lineage_portability_assessments(&latest_perf_samples)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].instance_id, instance);
        assert_eq!(resolved[0].runtime_session_id, runtime_session_id);
        assert_eq!(
            resolved[0].runtime_preflight_id,
            Some(runtime_preflight_id.clone())
        );
        assert_eq!(resolved[0].portability_assessment, supported_portability);

        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status["claim_status"].as_str(), Some("allowed"));
        assert_native_claim_status_portability(
            &status,
            Some(&supported_portability),
            UvmPortabilityAssessmentSource::LinkedRuntimePreflightLineage,
            Some(&runtime_session_id),
            Some(&runtime_preflight_id),
            None,
        );
    }

    #[tokio::test]
    async fn native_claim_status_preserves_allowed_behavior_when_session_lineage_has_no_preflight_link()
     {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id =
            persist_runtime_session_intent_lineage(temp.path(), &instance, None).await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let _host_evidence = create_measured_host_evidence(&service, &context).await;

        let latest_perf_samples = UvmObserveService::latest_perf_samples(
            service
                .active_perf_attestations()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let resolved = service
            .resolve_runtime_lineage_portability_assessments(&latest_perf_samples)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(resolved.is_empty());

        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status["claim_status"].as_str(), Some("allowed"));
        assert_native_claim_status_portability(
            &status,
            None,
            UvmPortabilityAssessmentSource::Unavailable,
            Some(&runtime_session_id),
            None,
            Some(
                UvmPortabilityAssessmentUnavailableReason::AuthoritativeRuntimeLineageMissingPortabilityEvidence,
            ),
        );
    }

    #[tokio::test]
    async fn native_claim_status_surfaces_authoritative_preflight_link_when_portability_is_unavailable()
     {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime_preflight_id =
            persist_runtime_preflight_portability_assessment(temp.path(), None).await;
        let runtime_session_id = persist_runtime_session_intent_lineage(
            temp.path(),
            &instance,
            Some(runtime_preflight_id.clone()),
        )
        .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let _host_evidence = create_measured_host_evidence(&service, &context).await;

        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status["claim_status"].as_str(), Some("allowed"));
        assert_native_claim_status_portability(
            &status,
            None,
            UvmPortabilityAssessmentSource::Unavailable,
            Some(&runtime_session_id),
            Some(&runtime_preflight_id),
            Some(
                UvmPortabilityAssessmentUnavailableReason::AuthoritativeRuntimeLineageMissingPortabilityEvidence,
            ),
        );
    }

    #[tokio::test]
    async fn native_claim_status_restricts_claims_when_runtime_lineage_portability_is_unsupported()
    {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let unsupported_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            Some(&UvmExecutionIntent {
                preferred_backend: Some(HypervisorBackend::Kvm),
                fallback_policy: UvmBackendFallbackPolicy::RequirePreferred,
                required_portability_tier: UvmPortabilityTier::Portable,
                evidence_strictness: UvmEvidenceStrictness::AllowSimulated,
            }),
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!unsupported_portability.supported);
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let runtime_preflight_id = persist_runtime_preflight_portability_assessment(
            temp.path(),
            Some(unsupported_portability.clone()),
        )
        .await;
        let runtime_session_id = persist_runtime_session_intent_lineage(
            temp.path(),
            &instance,
            Some(runtime_preflight_id.clone()),
        )
        .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let _host_evidence = create_measured_host_evidence(&service, &context).await;

        let latest_perf_samples = UvmObserveService::latest_perf_samples(
            service
                .active_perf_attestations()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let resolved = service
            .resolve_runtime_lineage_portability_assessments(&latest_perf_samples)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].instance_id, instance);
        assert_eq!(resolved[0].runtime_session_id, runtime_session_id);
        assert_eq!(
            resolved[0].runtime_preflight_id,
            Some(runtime_preflight_id.clone())
        );
        assert!(
            resolved[0]
                .portability_assessment
                .blockers
                .iter()
                .any(|value| value.contains("preferred backend kvm"))
        );

        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            status["native_indistinguishable_status"].as_bool(),
            Some(true)
        );
        assert_eq!(status["claim_status"].as_str(), Some("restricted"));
        assert_native_claim_status_portability(
            &status,
            Some(&unsupported_portability),
            UvmPortabilityAssessmentSource::LinkedRuntimePreflightLineage,
            Some(&runtime_session_id),
            Some(&runtime_preflight_id),
            None,
        );
    }

    #[tokio::test]
    async fn native_claim_status_does_not_resurrect_stale_runtime_preflight_when_authoritative_lineage_is_missing()
     {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let unsupported_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            Some(&UvmExecutionIntent {
                preferred_backend: Some(HypervisorBackend::Kvm),
                fallback_policy: UvmBackendFallbackPolicy::RequirePreferred,
                required_portability_tier: UvmPortabilityTier::Portable,
                evidence_strictness: UvmEvidenceStrictness::AllowSimulated,
            }),
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!unsupported_portability.supported);
        let supported_portability = assess_execution_intent(
            &BackendSelectionRequest {
                host: HostPlatform::Linux,
                candidates: vec![HypervisorBackend::SoftwareDbt, HypervisorBackend::Kvm],
                guest_architecture: GuestArchitecture::X86_64,
                apple_guest: false,
                requires_live_migration: false,
                require_secure_boot: false,
            },
            None,
            Some("direct_host"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));
        let stale_runtime_preflight_id = persist_runtime_preflight_portability_assessment(
            temp.path(),
            Some(unsupported_portability.clone()),
        )
        .await;
        let stale_runtime_session_id = persist_runtime_session_intent_lineage(
            temp.path(),
            &instance,
            Some(stale_runtime_preflight_id),
        )
        .await;
        soft_delete_runtime_session_presence(temp.path(), &stale_runtime_session_id).await;
        let authoritative_runtime_session_id =
            persist_runtime_session_intent_lineage_with_first_placement_portability(
                temp.path(),
                &instance,
                Some(supported_portability.clone()),
                None,
            )
            .await;

        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        create_strong_perf_samples(&service, &instance, &context).await;
        let _host_evidence = create_measured_host_evidence(&service, &context).await;

        let authoritative_status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            authoritative_status["claim_status"].as_str(),
            Some("allowed")
        );
        assert_native_claim_status_portability(
            &authoritative_status,
            Some(&supported_portability),
            UvmPortabilityAssessmentSource::FirstPlacementLineage,
            Some(&authoritative_runtime_session_id),
            None,
            None,
        );

        soft_delete_runtime_session_intent_lineage(temp.path(), &authoritative_runtime_session_id)
            .await;

        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status["claim_status"].as_str(), Some("allowed"));
        assert_native_claim_status_portability(
            &status,
            None,
            UvmPortabilityAssessmentSource::Unavailable,
            None,
            None,
            None,
        );
    }

    #[tokio::test]
    async fn benchmark_campaign_and_baseline_are_persisted() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let host_evidence = service
            .create_host_evidence(
                CreateHostEvidenceRequest {
                    evidence_mode: String::from("measured"),
                    host_platform: String::from("linux"),
                    execution_environment: String::from("bare_metal"),
                    hardware_virtualization: true,
                    nested_virtualization: true,
                    qemu_available: true,
                    note: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let host_evidence: UvmHostEvidenceRecord = response_json(host_evidence).await;

        let campaign = service
            .create_benchmark_campaign(
                CreateBenchmarkCampaignRequest {
                    name: String::from("linux-density"),
                    target: String::from("host"),
                    workload_class: String::from("general"),
                    require_qemu_baseline: Some(true),
                    require_container_baseline: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let campaign: UvmBenchmarkCampaignRecord = response_json(campaign).await;
        assert_eq!(campaign.state, "draft");

        let baseline = service
            .create_benchmark_baseline(
                CreateBenchmarkBaselineRequest {
                    campaign_id: campaign.id.to_string(),
                    engine: String::from("software_dbt"),
                    scenario: Some(String::from("service_readiness")),
                    guest_run_lineage: None,
                    measurement_mode: Some(String::from("direct")),
                    evidence_mode: String::from("measured"),
                    measured: true,
                    boot_time_ms: Some(125),
                    steady_state_score: Some(900),
                    control_plane_p99_ms: Some(12),
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    note: Some(String::from("pilot baseline")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let baseline: UvmBenchmarkBaselineRecord = response_json(baseline).await;
        assert_eq!(baseline.engine, "software_dbt");
        assert_eq!(baseline.host_evidence_id.as_ref(), Some(&host_evidence.id));
        assert_eq!(
            baseline.host_class_evidence_key.as_deref(),
            Some("linux_bare_metal")
        );
        assert_eq!(baseline.workload_class, "general");
        assert_eq!(baseline.scenario, "service_readiness");
        assert_eq!(baseline.measurement_mode.as_deref(), Some("direct"));
        assert_eq!(baseline.guest_run_lineage.as_deref(), None);

        let campaigns = service
            .list_benchmark_campaigns()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let baselines = service
            .list_benchmark_baselines()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(campaigns.len(), 1);
        assert_eq!(baselines.len(), 1);
    }

    #[tokio::test]
    async fn benchmark_summary_compares_results_against_baselines() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let host_evidence = create_measured_host_evidence(&service, &context).await;

        let campaign = service
            .create_benchmark_campaign(
                CreateBenchmarkCampaignRequest {
                    name: String::from("summary-campaign"),
                    target: String::from("host"),
                    workload_class: String::from("general"),
                    require_qemu_baseline: Some(true),
                    require_container_baseline: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let campaign: UvmBenchmarkCampaignRecord = response_json(campaign).await;

        for engine in ["software_dbt", "qemu", "container"] {
            let _ = service
                .create_benchmark_baseline(
                    CreateBenchmarkBaselineRequest {
                        campaign_id: campaign.id.to_string(),
                        engine: String::from(engine),
                        scenario: Some(String::from("cold_boot")),
                        guest_run_lineage: None,
                        measurement_mode: Some(String::from("direct")),
                        evidence_mode: String::from("measured"),
                        measured: true,
                        boot_time_ms: Some(100),
                        steady_state_score: Some(800),
                        control_plane_p99_ms: Some(15),
                        host_evidence_id: Some(host_evidence.id.to_string()),
                        note: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let _ = service
                .create_benchmark_result(
                    CreateBenchmarkResultRequest {
                        campaign_id: campaign.id.to_string(),
                        engine: String::from(engine),
                        scenario: String::from("cold_boot"),
                        guest_run_lineage: None,
                        measurement_mode: Some(String::from("direct")),
                        evidence_mode: String::from("measured"),
                        measured: true,
                        boot_time_ms: 95,
                        steady_state_score: 820,
                        control_plane_p99_ms: 14,
                        host_evidence_id: Some(host_evidence.id.to_string()),
                        note: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let summary = service
            .benchmark_summary(campaign.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary["status"].as_str(), Some("ready"));
        assert_eq!(
            summary["missing_baselines"].as_array().map(Vec::len),
            Some(0)
        );
        assert_eq!(summary["missing_results"].as_array().map(Vec::len), Some(0));
        assert_eq!(summary["comparisons"].as_array().map(Vec::len), Some(3));
        assert!(
            summary["comparisons"]
                .as_array()
                .unwrap_or_else(|| panic!("comparisons should be an array"))
                .iter()
                .all(|comparison| {
                    comparison["comparison_lineage"].as_str()
                        == Some("guest_run_lineage=host_scope measurement_mode=direct")
                })
        );
    }

    #[tokio::test]
    async fn measured_benchmark_rows_reuse_scope_key() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let host_evidence = create_measured_host_evidence(&service, &context).await;

        let campaign = service
            .create_benchmark_campaign(
                CreateBenchmarkCampaignRequest {
                    name: String::from("stable-scope"),
                    target: String::from("host"),
                    workload_class: String::from("general"),
                    require_qemu_baseline: Some(false),
                    require_container_baseline: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let campaign: UvmBenchmarkCampaignRecord = response_json(campaign).await;

        let baseline_response = service
            .create_benchmark_baseline(
                CreateBenchmarkBaselineRequest {
                    campaign_id: campaign.id.to_string(),
                    engine: String::from("software_dbt"),
                    scenario: Some(String::from("cold_boot")),
                    guest_run_lineage: None,
                    measurement_mode: Some(String::from("direct")),
                    evidence_mode: String::from("measured"),
                    measured: true,
                    boot_time_ms: Some(120),
                    steady_state_score: Some(900),
                    control_plane_p99_ms: Some(12),
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    note: Some(String::from("initial")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(baseline_response.status(), StatusCode::CREATED);
        let baseline: UvmBenchmarkBaselineRecord = response_json(baseline_response).await;

        let updated_baseline_response = service
            .create_benchmark_baseline(
                CreateBenchmarkBaselineRequest {
                    campaign_id: campaign.id.to_string(),
                    engine: String::from("software_dbt"),
                    scenario: Some(String::from("cold_boot")),
                    guest_run_lineage: None,
                    measurement_mode: Some(String::from("direct")),
                    evidence_mode: String::from("measured"),
                    measured: true,
                    boot_time_ms: Some(110),
                    steady_state_score: Some(940),
                    control_plane_p99_ms: Some(10),
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    note: Some(String::from("updated")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(updated_baseline_response.status(), StatusCode::OK);
        let updated_baseline: UvmBenchmarkBaselineRecord =
            response_json(updated_baseline_response).await;
        assert_eq!(updated_baseline.id, baseline.id);

        let result_response = service
            .create_benchmark_result(
                CreateBenchmarkResultRequest {
                    campaign_id: campaign.id.to_string(),
                    engine: String::from("software_dbt"),
                    scenario: String::from("cold_boot"),
                    guest_run_lineage: None,
                    measurement_mode: Some(String::from("direct")),
                    evidence_mode: String::from("measured"),
                    measured: true,
                    boot_time_ms: 98,
                    steady_state_score: 915,
                    control_plane_p99_ms: 11,
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    note: Some(String::from("initial")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(result_response.status(), StatusCode::CREATED);
        let result: UvmBenchmarkResultRecord = response_json(result_response).await;

        let updated_result_response = service
            .create_benchmark_result(
                CreateBenchmarkResultRequest {
                    campaign_id: campaign.id.to_string(),
                    engine: String::from("software_dbt"),
                    scenario: String::from("cold_boot"),
                    guest_run_lineage: None,
                    measurement_mode: Some(String::from("direct")),
                    evidence_mode: String::from("measured"),
                    measured: true,
                    boot_time_ms: 95,
                    steady_state_score: 930,
                    control_plane_p99_ms: 9,
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    note: Some(String::from("updated")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(updated_result_response.status(), StatusCode::OK);
        let updated_result: UvmBenchmarkResultRecord = response_json(updated_result_response).await;
        assert_eq!(updated_result.id, result.id);

        let baselines = service
            .list_benchmark_baselines()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let results = service
            .list_benchmark_results()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(baselines.len(), 1);
        assert_eq!(results.len(), 1);
        assert_eq!(baselines[0].boot_time_ms, Some(110));
        assert_eq!(results[0].boot_time_ms, 95);
        assert_eq!(results[0].measurement_mode.as_deref(), Some("direct"));
    }

    #[tokio::test]
    async fn measured_benchmark_result_rejects_conflicting_measurement_mode_within_scope() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let host_evidence = create_measured_host_evidence(&service, &context).await;

        let campaign = service
            .create_benchmark_campaign(
                CreateBenchmarkCampaignRequest {
                    name: String::from("measurement-mode-conflict"),
                    target: String::from("host"),
                    workload_class: String::from("general"),
                    require_qemu_baseline: Some(false),
                    require_container_baseline: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let campaign: UvmBenchmarkCampaignRecord = response_json(campaign).await;

        let _ = service
            .create_benchmark_result(
                CreateBenchmarkResultRequest {
                    campaign_id: campaign.id.to_string(),
                    engine: String::from("software_dbt"),
                    scenario: String::from("cold_boot"),
                    guest_run_lineage: None,
                    measurement_mode: Some(String::from("direct")),
                    evidence_mode: String::from("measured"),
                    measured: true,
                    boot_time_ms: 98,
                    steady_state_score: 915,
                    control_plane_p99_ms: 11,
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    note: Some(String::from("direct sample")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let err = service
            .create_benchmark_result(
                CreateBenchmarkResultRequest {
                    campaign_id: campaign.id.to_string(),
                    engine: String::from("software_dbt"),
                    scenario: String::from("cold_boot"),
                    guest_run_lineage: None,
                    measurement_mode: Some(String::from("hybrid")),
                    evidence_mode: String::from("measured"),
                    measured: true,
                    boot_time_ms: 95,
                    steady_state_score: 930,
                    control_plane_p99_ms: 9,
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    note: Some(String::from("hybrid sample")),
                },
                &context,
            )
            .await
            .expect_err("conflicting measurement_mode should be rejected");
        assert_eq!(err.code, uhost_core::ErrorCode::Conflict);
        assert_eq!(
            err.message,
            "measured benchmark result tuple already exists with different comparison lineage"
        );
        let detail = err.detail.unwrap_or_default();
        assert!(detail.contains("existing=guest_run_lineage=host_scope measurement_mode=direct"));
        assert!(detail.contains("requested=guest_run_lineage=host_scope measurement_mode=hybrid"));

        let results = service
            .list_benchmark_results()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].measurement_mode.as_deref(), Some("direct"));
    }

    #[tokio::test]
    async fn benchmark_summary_rejects_mixed_guest_run_lineage() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let host_evidence = create_measured_host_evidence(&service, &context).await;

        let campaign = service
            .create_benchmark_campaign(
                CreateBenchmarkCampaignRequest {
                    name: String::from("guest-lineage-mismatch"),
                    target: String::from("ubuntu_22_04_vm"),
                    workload_class: String::from("general"),
                    require_qemu_baseline: Some(false),
                    require_container_baseline: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let campaign: UvmBenchmarkCampaignRecord = response_json(campaign).await;

        let _ = service
            .create_benchmark_baseline(
                CreateBenchmarkBaselineRequest {
                    campaign_id: campaign.id.to_string(),
                    engine: String::from("software_dbt"),
                    scenario: Some(String::from("cold_boot")),
                    guest_run_lineage: Some(String::from("guest_run_a")),
                    measurement_mode: Some(String::from("direct")),
                    evidence_mode: String::from("measured"),
                    measured: true,
                    boot_time_ms: Some(100),
                    steady_state_score: Some(800),
                    control_plane_p99_ms: Some(10),
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    note: Some(String::from("guest lineage baseline")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_benchmark_result(
                CreateBenchmarkResultRequest {
                    campaign_id: campaign.id.to_string(),
                    engine: String::from("software_dbt"),
                    scenario: String::from("cold_boot"),
                    guest_run_lineage: Some(String::from("guest_run_b")),
                    measurement_mode: Some(String::from("direct")),
                    evidence_mode: String::from("measured"),
                    measured: true,
                    boot_time_ms: 95,
                    steady_state_score: 820,
                    control_plane_p99_ms: 9,
                    host_evidence_id: Some(host_evidence.id.to_string()),
                    note: Some(String::from("guest lineage result")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .benchmark_summary(campaign.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary["status"].as_str(), Some("incomplete"));
        assert_eq!(
            summary["missing_baselines"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(summary["missing_results"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            summary["missing_baselines"][0].as_str(),
            Some(
                "host_class=linux_bare_metal workload_class=general scenario=cold_boot engine=software_dbt guest_run_lineage=guest_run_b measurement_mode=direct"
            )
        );
        assert_eq!(
            summary["missing_results"][0].as_str(),
            Some(
                "host_class=linux_bare_metal workload_class=general scenario=cold_boot engine=software_dbt guest_run_lineage=guest_run_a measurement_mode=direct"
            )
        );
        assert_eq!(
            summary["comparisons"][0]["comparison_scope"].as_str(),
            Some(
                "host_class=linux_bare_metal workload_class=general scenario=cold_boot engine=software_dbt"
            )
        );
        assert_eq!(
            summary["comparisons"][0]["comparison_lineage"].as_str(),
            Some("guest_run_lineage=guest_run_b measurement_mode=direct")
        );
        assert_eq!(
            summary["comparisons"][0]["baseline_present"].as_bool(),
            Some(false)
        );
        assert_eq!(
            summary["comparisons"][0]["comparison_rejected_reason"].as_str(),
            Some(
                "mixed comparison lineage rejected: baseline guest_run_lineage=guest_run_a measurement_mode=direct but result guest_run_lineage=guest_run_b measurement_mode=direct"
            )
        );
    }

    #[tokio::test]
    async fn benchmark_summary_requires_matching_scope_for_measured_rows() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let baseline_host = create_measured_host_evidence(&service, &context).await;
        let hosted_ci = service
            .create_host_evidence(
                CreateHostEvidenceRequest {
                    evidence_mode: String::from("measured"),
                    host_platform: String::from("linux"),
                    execution_environment: String::from("hosted_ci"),
                    hardware_virtualization: false,
                    nested_virtualization: false,
                    qemu_available: true,
                    note: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let hosted_ci: UvmHostEvidenceRecord = response_json(hosted_ci).await;

        let campaign = service
            .create_benchmark_campaign(
                CreateBenchmarkCampaignRequest {
                    name: String::from("scope-mismatch"),
                    target: String::from("host"),
                    workload_class: String::from("general"),
                    require_qemu_baseline: Some(false),
                    require_container_baseline: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let campaign: UvmBenchmarkCampaignRecord = response_json(campaign).await;

        let _ = service
            .create_benchmark_baseline(
                CreateBenchmarkBaselineRequest {
                    campaign_id: campaign.id.to_string(),
                    engine: String::from("software_dbt"),
                    scenario: Some(String::from("cold_boot")),
                    guest_run_lineage: None,
                    measurement_mode: Some(String::from("direct")),
                    evidence_mode: String::from("measured"),
                    measured: true,
                    boot_time_ms: Some(100),
                    steady_state_score: Some(800),
                    control_plane_p99_ms: Some(10),
                    host_evidence_id: Some(baseline_host.id.to_string()),
                    note: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_benchmark_result(
                CreateBenchmarkResultRequest {
                    campaign_id: campaign.id.to_string(),
                    engine: String::from("software_dbt"),
                    scenario: String::from("cold_boot"),
                    guest_run_lineage: None,
                    measurement_mode: Some(String::from("direct")),
                    evidence_mode: String::from("measured"),
                    measured: true,
                    boot_time_ms: 95,
                    steady_state_score: 820,
                    control_plane_p99_ms: 9,
                    host_evidence_id: Some(hosted_ci.id.to_string()),
                    note: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .benchmark_summary(campaign.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary["status"].as_str(), Some("incomplete"));
        assert_eq!(
            summary["missing_baselines"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(
            summary["comparisons"][0]["baseline_present"].as_bool(),
            Some(false)
        );
        assert_eq!(
            summary["comparisons"][0]["comparison_scope"].as_str(),
            Some(
                "host_class=linux_hosted_ci workload_class=general scenario=cold_boot engine=software_dbt"
            )
        );
        assert_eq!(
            summary["comparisons"][0]["comparison_lineage"].as_str(),
            Some("guest_run_lineage=host_scope measurement_mode=direct")
        );
    }

    #[tokio::test]
    async fn generated_validation_reports_auto_ingest_into_keyed_benchmark_rows() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        write_generated_validation_bundle(temp.path());
        let state_root = temp.path().join("state");

        let service = UvmObserveService::open(&state_root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let campaigns = service
            .list_benchmark_campaigns()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(campaigns.len(), 1);
        let campaign = &campaigns[0];
        assert_eq!(campaign.name, "generated-validation-ubuntu_22_04_vm");
        assert_eq!(campaign.target, "ubuntu_22_04_vm");
        assert_eq!(
            campaign.workload_class,
            "generated_validation_ubuntu_22_04_vm"
        );
        assert!(campaign.require_qemu_baseline);
        assert!(!campaign.require_container_baseline);
        assert_eq!(campaign.state, "ready");

        let baselines = service
            .list_benchmark_baselines()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let results = service
            .list_benchmark_results()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(baselines.len(), 8);
        assert_eq!(results.len(), 8);
        assert!(
            baselines
                .iter()
                .all(|value| value.campaign_id == campaign.id)
        );
        assert!(results.iter().all(|value| value.campaign_id == campaign.id));

        let uvm_baseline = baselines
            .iter()
            .find(|value| value.engine == "software_dbt" && value.scenario == "steady_state")
            .unwrap_or_else(|| panic!("missing generated software_dbt steady_state baseline"));
        assert_eq!(
            uvm_baseline.host_class_evidence_key.as_deref(),
            Some("linux_container_restricted")
        );
        assert_eq!(
            uvm_baseline.guest_run_lineage.as_deref(),
            Some("wave3-core-generated-benchmark-evidence_ubuntu_22_04_vm")
        );
        assert_eq!(uvm_baseline.measurement_mode.as_deref(), Some("hybrid"));
        assert_eq!(uvm_baseline.evidence_mode, "prohibited");
        assert_eq!(uvm_baseline.boot_time_ms, Some(154));
        assert_eq!(uvm_baseline.steady_state_score, Some(13606));
        assert_eq!(uvm_baseline.control_plane_p99_ms, Some(20));
        assert!(
            uvm_baseline
                .note
                .as_deref()
                .unwrap_or_default()
                .contains("auto-ingested from docs/benchmarks/generated/ubuntu-validation.md")
        );

        let qemu_result = results
            .iter()
            .find(|value| value.engine == "qemu" && value.scenario == "migration_pressure")
            .unwrap_or_else(|| panic!("missing generated qemu migration_pressure result"));
        assert_eq!(
            qemu_result.host_class_evidence_key.as_deref(),
            Some("linux_container_restricted")
        );
        assert_eq!(
            qemu_result.guest_run_lineage.as_deref(),
            Some("wave3-core-generated-benchmark-evidence_ubuntu_22_04_vm")
        );
        assert_eq!(qemu_result.measurement_mode.as_deref(), Some("hybrid"));
        assert_eq!(qemu_result.evidence_mode, "simulated");
        assert_eq!(qemu_result.boot_time_ms, 748);
        assert_eq!(qemu_result.steady_state_score, 8412);
        assert_eq!(qemu_result.control_plane_p99_ms, 51);
        assert!(qemu_result.host_evidence_id.is_none());

        let baseline_store = DocumentStore::<UvmBenchmarkBaselineRecord>::open(
            state_root.join("uvm-observe/benchmark_baselines.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let baseline_rows = baseline_store
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(baseline_rows.iter().any(|(key, stored)| {
            key == "measured:linux_container_restricted:generated_validation_ubuntu_22_04_vm:steady_state:software_dbt"
                && !stored.deleted
        }));

        let result_store = DocumentStore::<UvmBenchmarkResultRecord>::open(
            state_root.join("uvm-observe/benchmark_results.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let result_rows = result_store
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(result_rows.iter().any(|(key, stored)| {
            key == "measured:linux_container_restricted:generated_validation_ubuntu_22_04_vm:migration_pressure:qemu"
                && !stored.deleted
        }));

        let summary = service
            .benchmark_summary(campaign.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary["status"].as_str(), Some("ready"));
        assert_eq!(
            summary["missing_baselines"].as_array().map(Vec::len),
            Some(0)
        );
        assert_eq!(summary["missing_results"].as_array().map(Vec::len), Some(0));
        assert_eq!(summary["comparisons"].as_array().map(Vec::len), Some(8));
    }

    #[tokio::test]
    async fn generated_validation_ingest_is_idempotent_across_reopen() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        write_generated_validation_bundle(temp.path());
        let state_root = temp.path().join("state");

        let first = UvmObserveService::open(&state_root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_campaigns = first
            .list_benchmark_campaigns()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_baselines = first
            .list_benchmark_baselines()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_results = first
            .list_benchmark_results()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        drop(first);

        let reopened = UvmObserveService::open(&state_root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let reopened_campaigns = reopened
            .list_benchmark_campaigns()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let reopened_baselines = reopened
            .list_benchmark_baselines()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let reopened_results = reopened
            .list_benchmark_results()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(reopened_campaigns, first_campaigns);
        assert_eq!(reopened_baselines, first_baselines);
        assert_eq!(reopened_results, first_results);
    }

    #[tokio::test]
    async fn generated_validation_ingest_supports_host_and_guest_targets() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        write_generated_validation_bundle_with_host_and_guest_reports(temp.path());
        let state_root = temp.path().join("state");

        let service = UvmObserveService::open(&state_root)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let campaigns = service
            .list_benchmark_campaigns()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(campaigns.len(), 2);

        let host_campaign = campaigns
            .iter()
            .find(|value| value.target == "host")
            .unwrap_or_else(|| panic!("missing generated host campaign"));
        assert_eq!(host_campaign.name, "generated-validation-host");
        assert_eq!(host_campaign.workload_class, "generated_validation_host");
        assert!(host_campaign.require_qemu_baseline);
        assert!(!host_campaign.require_container_baseline);

        let guest_campaign = campaigns
            .iter()
            .find(|value| value.target == "ubuntu_22_04_vm")
            .unwrap_or_else(|| panic!("missing generated guest campaign"));
        assert_eq!(
            guest_campaign.workload_class,
            "generated_validation_ubuntu_22_04_vm"
        );

        let baselines = service
            .list_benchmark_baselines()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let results = service
            .list_benchmark_results()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let host_baseline = baselines
            .iter()
            .find(|value| {
                value.campaign_id == host_campaign.id
                    && value.engine == "software_dbt"
                    && value.scenario == "cold_boot"
            })
            .unwrap_or_else(|| panic!("missing generated host software_dbt baseline"));
        assert_eq!(
            host_baseline.host_class_evidence_key.as_deref(),
            Some("linux_bare_metal")
        );
        assert_eq!(host_baseline.guest_run_lineage.as_deref(), None);
        assert_eq!(host_baseline.measurement_mode.as_deref(), Some("direct"));
        assert_eq!(host_baseline.evidence_mode, "measured");

        let host_result = results
            .iter()
            .find(|value| {
                value.campaign_id == host_campaign.id
                    && value.engine == "qemu"
                    && value.scenario == "service_readiness"
            })
            .unwrap_or_else(|| panic!("missing generated host qemu result"));
        assert_eq!(
            host_result.host_class_evidence_key.as_deref(),
            Some("linux_bare_metal")
        );
        assert_eq!(host_result.guest_run_lineage.as_deref(), None);
        assert_eq!(host_result.measurement_mode.as_deref(), Some("direct"));
        assert_eq!(host_result.evidence_mode, "simulated");

        assert!(
            baselines
                .iter()
                .any(|value| value.campaign_id == guest_campaign.id)
        );
        assert!(
            results
                .iter()
                .any(|value| value.campaign_id == guest_campaign.id)
        );
    }

    #[tokio::test]
    async fn perf_attestation_post_is_idempotent_and_sorted() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let alpha = service
            .create_perf_attestation(
                CreatePerfAttestationRequest {
                    instance_id: instance.to_string(),
                    workload_class: String::from("  alpha  "),
                    claim_tier: None,
                    claim_evidence_mode: None,
                    cpu_overhead_pct: 4,
                    memory_overhead_pct: 4,
                    block_io_latency_overhead_pct: 8,
                    network_latency_overhead_pct: 8,
                    jitter_pct: 7,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(alpha.status(), StatusCode::CREATED);
        let alpha_payload = BodyExt::collect(alpha.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let alpha_record: super::UvmPerfAttestationRecord =
            serde_json::from_slice(&alpha_payload).unwrap_or_else(|error| panic!("{error}"));

        let replay = service
            .create_perf_attestation(
                CreatePerfAttestationRequest {
                    instance_id: instance.to_string(),
                    workload_class: String::from("alpha"),
                    claim_tier: None,
                    claim_evidence_mode: None,
                    cpu_overhead_pct: 4,
                    memory_overhead_pct: 4,
                    block_io_latency_overhead_pct: 8,
                    network_latency_overhead_pct: 8,
                    jitter_pct: 7,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replay.status(), StatusCode::OK);
        let replay_payload = BodyExt::collect(replay.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let replay_record: super::UvmPerfAttestationRecord =
            serde_json::from_slice(&replay_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(alpha_record.id, replay_record.id);
        assert_eq!(
            service
                .outbox
                .list_all()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            1
        );

        let beta = service
            .create_perf_attestation(
                CreatePerfAttestationRequest {
                    instance_id: instance.to_string(),
                    workload_class: String::from("beta"),
                    claim_tier: None,
                    claim_evidence_mode: None,
                    cpu_overhead_pct: 4,
                    memory_overhead_pct: 4,
                    block_io_latency_overhead_pct: 8,
                    network_latency_overhead_pct: 8,
                    jitter_pct: 7,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(beta.status(), StatusCode::CREATED);

        let ordered = service
            .active_perf_attestations()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].workload_class, "alpha");
        assert_eq!(ordered[1].workload_class, "beta");
    }

    #[tokio::test]
    async fn failure_report_post_is_idempotent_and_validates_input() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("operator");

        let first = service
            .create_failure_report(
                CreateFailureReportRequest {
                    instance_id: None,
                    category: String::from("  kernel-panic "),
                    severity: String::from(" critical "),
                    summary: String::from("  watchdog reset after fault  "),
                    recovered: false,
                    forensic_capture_requested: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first.status(), StatusCode::CREATED);
        let first_payload = BodyExt::collect(first.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let first_record: super::UvmFailureReportRecord =
            serde_json::from_slice(&first_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first_record.category, "kernel-panic");
        assert_eq!(first_record.severity, "critical");
        assert_eq!(first_record.summary, "watchdog reset after fault");

        let replay = service
            .create_failure_report(
                CreateFailureReportRequest {
                    instance_id: None,
                    category: String::from("kernel-panic"),
                    severity: String::from("critical"),
                    summary: String::from("watchdog reset after fault"),
                    recovered: false,
                    forensic_capture_requested: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replay.status(), StatusCode::OK);
        let replay_payload = BodyExt::collect(replay.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let replay_record: super::UvmFailureReportRecord =
            serde_json::from_slice(&replay_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first_record.id, replay_record.id);
        assert_eq!(
            service
                .outbox
                .list_all()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn native_claim_status_ignores_soft_deleted_samples() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let perf = service
            .create_perf_attestation(
                CreatePerfAttestationRequest {
                    instance_id: instance.to_string(),
                    workload_class: String::from("general"),
                    claim_tier: None,
                    claim_evidence_mode: None,
                    cpu_overhead_pct: 4,
                    memory_overhead_pct: 4,
                    block_io_latency_overhead_pct: 8,
                    network_latency_overhead_pct: 8,
                    jitter_pct: 7,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let perf_payload = BodyExt::collect(perf.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let perf_record: super::UvmPerfAttestationRecord =
            serde_json::from_slice(&perf_payload).unwrap_or_else(|error| panic!("{error}"));
        service
            .perf_attestations
            .soft_delete(
                &super::perf_request_fingerprint(
                    &perf_record.instance_id,
                    &perf_record.workload_class,
                    perf_record.cpu_overhead_pct,
                    perf_record.memory_overhead_pct,
                    perf_record.block_io_latency_overhead_pct,
                    perf_record.network_latency_overhead_pct,
                    perf_record.jitter_pct,
                ),
                Some(1),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let failure = service
            .create_failure_report(
                CreateFailureReportRequest {
                    instance_id: Some(instance.to_string()),
                    category: String::from("kernel"),
                    severity: String::from("critical"),
                    summary: String::from("kernel panic"),
                    recovered: false,
                    forensic_capture_requested: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let failure_payload = BodyExt::collect(failure.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let failure_record: super::UvmFailureReportRecord =
            serde_json::from_slice(&failure_payload).unwrap_or_else(|error| panic!("{error}"));
        service
            .failure_reports
            .soft_delete(
                &super::failure_report_fingerprint(
                    failure_record.instance_id.as_ref(),
                    &failure_record.category,
                    &failure_record.severity,
                    &failure_record.summary,
                    failure_record.recovered,
                    failure_record.forensic_capture_requested,
                ),
                Some(1),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status["perf_samples"], 0);
        assert_eq!(status["critical_unrecovered_failures"], false);
        assert!(
            !status["missing_required_workload_classes"]
                .as_array()
                .unwrap_or(&Vec::new())
                .is_empty()
        );
        assert!(
            !status["native_indistinguishable_status"]
                .as_bool()
                .unwrap_or(true)
        );
    }

    #[tokio::test]
    async fn native_claim_status_requires_required_workloads() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_perf_attestation(
                CreatePerfAttestationRequest {
                    instance_id: instance.to_string(),
                    workload_class: String::from("general"),
                    claim_tier: None,
                    claim_evidence_mode: None,
                    cpu_overhead_pct: 4,
                    memory_overhead_pct: 4,
                    block_io_latency_overhead_pct: 8,
                    network_latency_overhead_pct: 8,
                    jitter_pct: 7,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            !status["native_indistinguishable_status"]
                .as_bool()
                .unwrap_or(true)
        );
        assert!(
            !status["missing_required_workload_classes"]
                .as_array()
                .unwrap_or(&Vec::new())
                .is_empty()
        );
    }

    #[tokio::test]
    async fn native_claim_status_reports_failing_workloads() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let instance = UvmInstanceId::generate().unwrap_or_else(|error| panic!("{error}"));

        for &workload_class in REQUIRED_WORKLOAD_CLASSES {
            let (cpu, memory) = if workload_class == "cpu_intensive" {
                (12, 4)
            } else {
                (4, 4)
            };
            let _ = service
                .create_perf_attestation(
                    CreatePerfAttestationRequest {
                        instance_id: instance.to_string(),
                        workload_class: workload_class.to_string(),
                        claim_tier: None,
                        claim_evidence_mode: None,
                        cpu_overhead_pct: cpu,
                        memory_overhead_pct: memory,
                        block_io_latency_overhead_pct: 8,
                        network_latency_overhead_pct: 8,
                        jitter_pct: 7,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let status = service
            .native_claim_status()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            !status["native_indistinguishable_status"]
                .as_bool()
                .unwrap_or(true)
        );
        let failing = status["failing_workload_classes"]
            .as_array()
            .expect("failing_workload_classes must be an array")
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>();
        assert!(failing.contains(&"cpu_intensive"));
    }

    #[tokio::test]
    async fn perf_validation_rejects_out_of_range_percentages() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let err = service
            .create_perf_attestation(
                CreatePerfAttestationRequest {
                    instance_id: UvmInstanceId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    workload_class: String::from("general"),
                    claim_tier: None,
                    claim_evidence_mode: None,
                    cpu_overhead_pct: 101,
                    memory_overhead_pct: 4,
                    block_io_latency_overhead_pct: 8,
                    network_latency_overhead_pct: 8,
                    jitter_pct: 7,
                },
                &context,
            )
            .await
            .expect_err("invalid percentage should be rejected");
        assert_eq!(err.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn failure_validation_rejects_empty_fields() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let err = service
            .create_failure_report(
                CreateFailureReportRequest {
                    instance_id: None,
                    category: String::from("kernel"),
                    severity: String::from("  "),
                    summary: String::from("watchdog reset"),
                    recovered: false,
                    forensic_capture_requested: None,
                },
                &context,
            )
            .await
            .expect_err("blank severity should be rejected");
        assert_eq!(err.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn failure_validation_rejects_unknown_severity() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let err = service
            .create_failure_report(
                CreateFailureReportRequest {
                    instance_id: None,
                    category: String::from("kernel"),
                    severity: String::from("sev0"),
                    summary: String::from("watchdog reset"),
                    recovered: false,
                    forensic_capture_requested: None,
                },
                &context,
            )
            .await
            .expect_err("unknown severity should be rejected");
        assert_eq!(err.code, uhost_core::ErrorCode::InvalidInput);
    }
}
