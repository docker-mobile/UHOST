//! Observability configuration and analysis service.
//!
//! This bounded context exposes control-plane primitives for OTLP export
//! targets, alerting routes, SLI/SLO definitions, error-budget reporting, and
//! slow-path exemplar correlation.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};

use http::{Method, Request, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{PlatformError, RequestContext, Result, sha256_hex};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{
    CellDirectoryRecord, CellParticipantDrainPhase, CellParticipantState, DocumentStore,
    LeaseDrainIntent, LeaseFreshness, LeaseReadiness, StoredDocument, WorkflowInstance,
    WorkflowPhase,
};
use uhost_types::{
    AlertRuleId, AuditId, NodeId, OwnershipScope, ResourceMetadata, RouteId, WorkloadId,
};

/// Alert rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: AlertRuleId,
    pub name: String,
    pub expression: String,
    pub severity: String,
    pub enabled: bool,
    pub metadata: ResourceMetadata,
}

/// Activity log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub id: AuditId,
    pub category: String,
    pub summary: String,
    pub correlation_id: Option<String>,
    pub created_at: OffsetDateTime,
}

/// OTLP exporter target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtlpExporter {
    pub id: AuditId,
    pub signal: String,
    pub endpoint: String,
    pub insecure: bool,
    pub headers: BTreeMap<String, String>,
    pub enabled: bool,
    pub metadata: ResourceMetadata,
}

/// OTLP dispatch attempt record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtlpDispatchAttempt {
    pub id: AuditId,
    pub exporter_id: AuditId,
    pub signal: String,
    pub batch_items: u32,
    pub payload_bytes: u64,
    pub status: String,
    pub latency_ms: u64,
    pub error: Option<String>,
    pub created_at: OffsetDateTime,
}

/// SLO definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SloDefinition {
    pub id: AlertRuleId,
    pub name: String,
    pub sli_kind: String,
    pub target_success_per_million: u32,
    pub window_minutes: u32,
    pub alert_route_id: Option<RouteId>,
    pub metadata: ResourceMetadata,
}

/// Alert routing policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRoutePolicy {
    pub id: RouteId,
    pub name: String,
    pub destination: String,
    pub severity_filter: Vec<String>,
    pub metadata: ResourceMetadata,
}

/// Slow-path observation entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlowPathEntry {
    pub id: AuditId,
    pub category: String,
    pub resource: String,
    pub latency_ms: u64,
    pub exemplar_trace_id: Option<String>,
    pub observed_at: OffsetDateTime,
}

/// Computed error budget snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBudgetSnapshot {
    pub slo_id: AlertRuleId,
    pub slo_name: String,
    pub success_target_per_million: u32,
    pub measured_success_per_million: u32,
    pub budget_remaining_per_million: u32,
    pub window_minutes: u32,
}

/// Routed incident created from alert-rule or SLO evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserveIncident {
    pub id: AuditId,
    pub source_kind: String,
    pub source_id: String,
    pub severity: String,
    pub summary: String,
    pub route_id: Option<RouteId>,
    pub destination: Option<String>,
    pub status: String,
    pub correlation_id: Option<String>,
    pub created_at: OffsetDateTime,
    pub resolved_at: Option<OffsetDateTime>,
    pub metadata: ResourceMetadata,
}

/// Evaluation summary for generated incidents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentEvaluationReport {
    pub evaluated_rules: usize,
    pub evaluated_slos: usize,
    pub incidents_created: usize,
    pub incidents: Vec<ObserveIncident>,
}

/// Summarized node health information derived from local state files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeHealthSummary {
    pub state_root: String,
    pub heartbeats_available: bool,
    pub process_reports_available: bool,
    pub total_nodes: usize,
    pub healthy_nodes: usize,
    pub unhealthy_nodes: usize,
    pub total_process_reports: usize,
    pub unique_workloads: usize,
    pub recent_heartbeats: Vec<NodeHeartbeatSummary>,
    pub process_report_totals: Vec<ProcessReportTotals>,
}

/// Snapshot exposed for recent node heartbeats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeHeartbeatSummary {
    pub node_id: NodeId,
    pub hostname: String,
    pub healthy: bool,
    pub agent_version: String,
    pub last_seen: OffsetDateTime,
    pub reported_workloads: usize,
}

/// Aggregated totals for process reports grouped by state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessReportTotals {
    pub state: String,
    pub report_count: usize,
    pub unique_nodes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserveSummary {
    pub alert_rule_count: usize,
    pub activity_count: usize,
    pub activity_category_counts: BTreeMap<String, usize>,
    pub otlp_exporter_count: usize,
    pub otlp_exporter_enabled_count: usize,
    pub otlp_dispatch_count: usize,
    pub dispatch_status_counts: BTreeMap<String, usize>,
    pub slo_count: usize,
    pub slo_window_minutes: BTreeMap<u32, usize>,
    pub alert_route_count: usize,
    pub slow_path_count: usize,
    pub incident_count: usize,
    pub incident_status_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetOpsRollups {
    pub state_root: String,
    pub generated_at: OffsetDateTime,
    pub ha_readiness: FleetOpsHaReadinessRollup,
    pub incident_state: FleetOpsIncidentStateRollup,
    pub backlog_health: FleetOpsBacklogHealthRollup,
    pub regions: Vec<RegionFleetOpsRollup>,
    pub cells: Vec<CellFleetOpsRollup>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetOpsHaReadinessRollup {
    pub total_regions: usize,
    pub ready_regions: usize,
    pub degraded_regions: usize,
    pub regions_missing_reconciliation: usize,
    pub unreconciled_regions: usize,
    pub total_cells: usize,
    pub ready_cells: usize,
    pub degraded_cells: usize,
    pub critical_dependencies_down: usize,
    pub critical_dependencies_degraded: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetOpsIncidentStateRollup {
    pub total_incidents: usize,
    pub open_incidents: usize,
    pub resolved_incidents: usize,
    pub status_counts: BTreeMap<String, usize>,
    pub severity_counts: BTreeMap<String, usize>,
    pub attributed_region_incidents: usize,
    pub attributed_cell_incidents: usize,
    pub unattributed_incidents: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetOpsBacklogHealthRollup {
    pub attention_items: usize,
    pub critical_items: usize,
    pub ha_failovers_in_progress: usize,
    pub ha_failovers_failed: usize,
    pub ha_repair_workflows_active: usize,
    pub ha_repair_workflows_failed: usize,
    pub lifecycle_dead_letters_pending: usize,
    pub lifecycle_repair_jobs_active: usize,
    pub lifecycle_repair_jobs_failed: usize,
    pub data_failovers_active: usize,
    pub data_failovers_failed: usize,
    pub data_migrations_active: usize,
    pub data_migrations_failed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionFleetOpsRollup {
    pub region_id: String,
    pub region_name: String,
    pub ha_readiness: RegionHaReadinessRollup,
    pub incident_state: ScopedIncidentRollup,
    pub backlog_health: RegionBacklogHealthRollup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionHaReadinessRollup {
    pub total_cells: usize,
    pub ready_cells: usize,
    pub degraded_cells: usize,
    pub participant_count: usize,
    pub reconciliation_available: bool,
    pub fully_reconciled: bool,
    pub healthy_votes: Option<u64>,
    pub majority_threshold: Option<u64>,
    pub uncommitted_entries: u64,
    pub lagging_nodes: usize,
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionBacklogHealthRollup {
    pub attention_items: usize,
    pub critical_items: usize,
    pub uncommitted_entries: u64,
    pub lagging_nodes: usize,
    pub data_migrations_active: usize,
    pub data_migrations_failed: usize,
    pub data_failovers_active: usize,
    pub data_failovers_failed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellFleetOpsRollup {
    pub cell_id: String,
    pub cell_name: String,
    pub region_id: String,
    pub region_name: String,
    pub ha_readiness: CellHaReadinessRollup,
    pub incident_state: ScopedIncidentRollup,
    pub backlog_health: CellBacklogHealthRollup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellHaReadinessRollup {
    pub participant_count: usize,
    pub serving_participants: usize,
    pub draining_participants: usize,
    pub degraded_participants: usize,
    pub stale_participants: usize,
    pub expired_participants: usize,
    pub ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellBacklogHealthRollup {
    pub attention_items: usize,
    pub critical_items: usize,
    pub stale_participants: usize,
    pub expired_participants: usize,
    pub takeover_pending: usize,
    pub takeover_acknowledged: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedIncidentRollup {
    pub total_incidents: usize,
    pub open_incidents: usize,
    pub status_counts: BTreeMap<String, usize>,
    pub severity_counts: BTreeMap<String, usize>,
}

mod node_state {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NodeHeartbeatRecord {
        pub node_id: NodeId,
        pub hostname: String,
        pub healthy: bool,
        pub agent_version: String,
        pub cache_bytes: u64,
        pub last_seen: OffsetDateTime,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ProcessReportRecord {
        pub node_id: NodeId,
        pub workload_id: WorkloadId,
        pub state: String,
        pub exit_code: Option<i32>,
        pub updated_at: OffsetDateTime,
    }
}

mod ha_state {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ReconciliationRecord {
        pub region: String,
        pub latest_log_index: u64,
        pub committed_log_index: u64,
        pub majority_threshold: u64,
        pub healthy_votes: u64,
        pub uncommitted_entries: u64,
        #[serde(default)]
        pub lagging_nodes: Vec<String>,
        pub fully_reconciled: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DependencyStatusRecord {
        pub dependency: String,
        pub status: String,
        pub critical: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct FailoverRecord {
        pub state: String,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RepairWorkflowState;

    pub type RepairWorkflow = WorkflowInstance<RepairWorkflowState>;
}

mod lifecycle_state {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DeadLetterRecord {
        pub replayed: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RepairJobRecord {
        pub status: String,
    }

    pub type RepairJobWorkflow = WorkflowInstance<RepairJobRecord>;
}

mod data_state {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DataFailoverRecord {
        pub state: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DataMigrationJob {
        pub state: String,
        #[serde(default)]
        pub source_region: Option<String>,
        #[serde(default)]
        pub target_region: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct FailoverWorkflowState {
        pub target_region: String,
    }

    pub type FailoverWorkflow = WorkflowInstance<FailoverWorkflowState>;
}

#[derive(Debug, Default)]
struct RegionAccumulator {
    region_name: String,
    total_cells: usize,
    ready_cells: usize,
    degraded_cells: usize,
    participant_count: usize,
    reconciliation_available: bool,
    fully_reconciled: bool,
    healthy_votes: Option<u64>,
    majority_threshold: Option<u64>,
    uncommitted_entries: u64,
    lagging_nodes: usize,
    incident_total: usize,
    incident_open: usize,
    incident_status_counts: BTreeMap<String, usize>,
    incident_severity_counts: BTreeMap<String, usize>,
    data_migrations_active: usize,
    data_migrations_failed: usize,
    data_failovers_active: usize,
    data_failovers_failed: usize,
}

#[derive(Debug, Default)]
struct CellAccumulator {
    cell_name: String,
    region_id: String,
    region_name: String,
    participant_count: usize,
    serving_participants: usize,
    draining_participants: usize,
    degraded_participants: usize,
    stale_participants: usize,
    expired_participants: usize,
    takeover_pending: usize,
    takeover_acknowledged: usize,
    incident_total: usize,
    incident_open: usize,
    incident_status_counts: BTreeMap<String, usize>,
    incident_severity_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Default)]
struct CellMetrics {
    participant_count: usize,
    serving_participants: usize,
    draining_participants: usize,
    degraded_participants: usize,
    stale_participants: usize,
    expired_participants: usize,
    takeover_pending: usize,
    takeover_acknowledged: usize,
}

#[derive(Debug, Default)]
struct RepairJobBacklogCounts {
    active: usize,
    failed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateAlertRuleRequest {
    name: String,
    expression: String,
    severity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateActivityRequest {
    category: String,
    summary: String,
    correlation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateOtlpExporterRequest {
    signal: String,
    endpoint: String,
    insecure: bool,
    headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateSloRequest {
    name: String,
    sli_kind: String,
    target_success_per_million: u32,
    window_minutes: u32,
    alert_route_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateAlertRouteRequest {
    name: String,
    destination: String,
    severity_filter: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateSlowPathRequest {
    category: String,
    resource: String,
    latency_ms: u64,
    exemplar_trace_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateOtlpDispatchRequest {
    exporter_id: String,
    batch_items: u32,
    payload_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EvaluateIncidentsRequest {
    include_alert_rules: Option<bool>,
    include_slos: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ResolveIncidentRequest {
    reason: Option<String>,
}

/// Observe service.
#[derive(Debug, Clone)]
pub struct ObserveService {
    alert_rules: DocumentStore<AlertRule>,
    activity: DocumentStore<ActivityEntry>,
    otlp_exporters: DocumentStore<OtlpExporter>,
    otlp_dispatch: DocumentStore<OtlpDispatchAttempt>,
    slos: DocumentStore<SloDefinition>,
    alert_routes: DocumentStore<AlertRoutePolicy>,
    slow_paths: DocumentStore<SlowPathEntry>,
    incidents: DocumentStore<ObserveIncident>,
    state_root: PathBuf,
}

impl ObserveService {
    /// Open observe state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("observe");
        Ok(Self {
            alert_rules: DocumentStore::open(root.join("alert_rules.json")).await?,
            activity: DocumentStore::open(root.join("activity.json")).await?,
            otlp_exporters: DocumentStore::open(root.join("otlp_exporters.json")).await?,
            otlp_dispatch: DocumentStore::open(root.join("otlp_dispatch.json")).await?,
            slos: DocumentStore::open(root.join("slos.json")).await?,
            alert_routes: DocumentStore::open(root.join("alert_routes.json")).await?,
            slow_paths: DocumentStore::open(root.join("slow_paths.json")).await?,
            incidents: DocumentStore::open(root.join("incidents.json")).await?,
            state_root: root,
        })
    }

    fn platform_root(&self) -> &Path {
        self.state_root
            .parent()
            .unwrap_or_else(|| self.state_root.as_ref())
    }

    fn read_active_collection<T: DeserializeOwned>(path: &Path) -> Option<Vec<T>> {
        let file = File::open(path).ok()?;
        let payload: Value = serde_json::from_reader(file).ok()?;
        let records = payload.get("records")?.as_object()?;
        let mut values = Vec::with_capacity(records.len());
        for record in records.values() {
            if record
                .get("deleted")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                continue;
            }
            let value = record.get("value")?.clone();
            values.push(serde_json::from_value(value).ok()?);
        }
        Some(values)
    }

    fn lifecycle_repair_job_backlog_counts(platform_root: &Path) -> RepairJobBacklogCounts {
        let workflow_path = platform_root.join("lifecycle/repair_job_workflows.json");
        if workflow_path.is_file() {
            let workflows =
                Self::read_active_collection::<lifecycle_state::RepairJobWorkflow>(&workflow_path)
                    .unwrap_or_default();
            return RepairJobBacklogCounts {
                active: workflows
                    .iter()
                    .filter(|workflow| workflow_phase_is_active(&workflow.phase))
                    .count(),
                failed: workflows
                    .iter()
                    .filter(|workflow| workflow_phase_is_failed(&workflow.phase))
                    .count(),
            };
        }

        let repair_jobs = Self::read_active_collection::<lifecycle_state::RepairJobRecord>(
            &platform_root.join("lifecycle/repair_jobs.json"),
        )
        .unwrap_or_default();
        RepairJobBacklogCounts {
            active: repair_jobs
                .iter()
                .filter(|record| repair_job_state_is_active(&record.status))
                .count(),
            failed: repair_jobs
                .iter()
                .filter(|record| repair_job_state_is_failed(&record.status))
                .count(),
        }
    }

    fn node_health_summary(&self) -> NodeHealthSummary {
        let platform_root = self.platform_root();
        let heartbeats = Self::read_active_collection::<node_state::NodeHeartbeatRecord>(
            &platform_root.join("node/heartbeats.json"),
        );
        let process_reports = Self::read_active_collection::<node_state::ProcessReportRecord>(
            &platform_root.join("node/process_reports.json"),
        );
        let heartbeats_available = heartbeats.is_some();
        let process_reports_available = process_reports.is_some();
        let mut heartbeats = heartbeats.unwrap_or_default();
        let process_reports = process_reports.unwrap_or_default();

        let mut workload_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut process_state_totals: BTreeMap<String, (usize, HashSet<String>)> = BTreeMap::new();
        let mut unique_workloads = HashSet::new();
        for report in &process_reports {
            *workload_counts
                .entry(report.node_id.to_string())
                .or_default() += 1;
            unique_workloads.insert(report.workload_id.to_string());
            let state_entry = process_state_totals
                .entry(report.state.clone())
                .or_insert_with(|| (0, HashSet::new()));
            state_entry.0 = state_entry.0.saturating_add(1);
            state_entry.1.insert(report.node_id.to_string());
        }

        heartbeats.sort_by_key(|heartbeat| {
            (
                heartbeat.healthy,
                Reverse(heartbeat.last_seen),
                heartbeat.hostname.clone(),
                heartbeat.node_id.to_string(),
            )
        });

        let healthy_nodes = heartbeats
            .iter()
            .filter(|heartbeat| heartbeat.healthy)
            .count();
        let unhealthy_nodes = heartbeats.len().saturating_sub(healthy_nodes);
        let recent_heartbeats = heartbeats
            .into_iter()
            .map(|heartbeat| NodeHeartbeatSummary {
                reported_workloads: workload_counts
                    .get(heartbeat.node_id.as_str())
                    .copied()
                    .unwrap_or_default(),
                node_id: heartbeat.node_id,
                hostname: heartbeat.hostname,
                healthy: heartbeat.healthy,
                agent_version: heartbeat.agent_version,
                last_seen: heartbeat.last_seen,
            })
            .collect();
        let mut process_report_totals = process_state_totals
            .into_iter()
            .map(
                |(state, (report_count, unique_nodes))| ProcessReportTotals {
                    state,
                    report_count,
                    unique_nodes: unique_nodes.len(),
                },
            )
            .collect::<Vec<_>>();
        process_report_totals.sort_by(|left, right| {
            right
                .report_count
                .cmp(&left.report_count)
                .then(left.state.cmp(&right.state))
        });

        NodeHealthSummary {
            state_root: platform_root.display().to_string(),
            heartbeats_available,
            process_reports_available,
            total_nodes: healthy_nodes.saturating_add(unhealthy_nodes),
            healthy_nodes,
            unhealthy_nodes,
            total_process_reports: process_reports.len(),
            unique_workloads: unique_workloads.len(),
            recent_heartbeats,
            process_report_totals,
        }
    }

    async fn observe_summary(&self) -> Result<ObserveSummary> {
        let alert_rules = active_records(self.alert_rules.list().await?);
        let activity = active_records(self.activity.list().await?);
        let otlp_exporters = active_records(self.otlp_exporters.list().await?);
        let otlp_dispatch = active_records(self.otlp_dispatch.list().await?);
        let slos = active_records(self.slos.list().await?);
        let alert_routes = active_records(self.alert_routes.list().await?);
        let slow_paths = active_records(self.slow_paths.list().await?);
        let incidents = active_records(self.incidents.list().await?);

        let mut activity_category_counts = BTreeMap::new();
        for entry in &activity {
            *activity_category_counts
                .entry(entry.category.clone())
                .or_default() += 1;
        }

        let otlp_exporter_enabled_count = otlp_exporters
            .iter()
            .filter(|exporter| exporter.enabled)
            .count();

        let mut dispatch_status_counts = BTreeMap::new();
        for attempt in &otlp_dispatch {
            *dispatch_status_counts
                .entry(attempt.status.clone())
                .or_default() += 1;
        }

        let mut slo_window_minutes = BTreeMap::new();
        for slo in &slos {
            *slo_window_minutes.entry(slo.window_minutes).or_default() += 1;
        }

        let mut incident_status_counts = BTreeMap::new();
        for incident in &incidents {
            *incident_status_counts
                .entry(incident.status.clone())
                .or_default() += 1;
        }

        Ok(ObserveSummary {
            alert_rule_count: alert_rules.len(),
            activity_count: activity.len(),
            activity_category_counts,
            otlp_exporter_count: otlp_exporters.len(),
            otlp_exporter_enabled_count,
            otlp_dispatch_count: otlp_dispatch.len(),
            dispatch_status_counts,
            slo_count: slos.len(),
            slo_window_minutes,
            alert_route_count: alert_routes.len(),
            slow_path_count: slow_paths.len(),
            incident_count: incidents.len(),
            incident_status_counts,
        })
    }

    async fn fleet_ops_rollups(&self) -> Result<FleetOpsRollups> {
        let platform_root = self.platform_root().to_path_buf();
        let generated_at = OffsetDateTime::now_utc();

        let incidents = active_records(self.incidents.list().await?);
        let cell_directory = Self::read_active_collection::<CellDirectoryRecord>(
            &platform_root.join("runtime/cell-directory.json"),
        )
        .unwrap_or_default();
        let reconciliations = Self::read_active_collection::<ha_state::ReconciliationRecord>(
            &platform_root.join("ha/reconciliations.json"),
        )
        .unwrap_or_default();
        let dependencies = Self::read_active_collection::<ha_state::DependencyStatusRecord>(
            &platform_root.join("ha/dependencies.json"),
        )
        .unwrap_or_default();
        let ha_failovers = Self::read_active_collection::<ha_state::FailoverRecord>(
            &platform_root.join("ha/failovers.json"),
        )
        .unwrap_or_default();
        let ha_repair_workflows = Self::read_active_collection::<ha_state::RepairWorkflow>(
            &platform_root.join("ha/repair_workflows.json"),
        )
        .unwrap_or_default();
        let dead_letters = Self::read_active_collection::<lifecycle_state::DeadLetterRecord>(
            &platform_root.join("lifecycle/dead_letters.json"),
        )
        .unwrap_or_default();
        let lifecycle_repair_jobs = Self::lifecycle_repair_job_backlog_counts(&platform_root);
        let data_failovers = Self::read_active_collection::<data_state::DataFailoverRecord>(
            &platform_root.join("data/failovers.json"),
        )
        .unwrap_or_default();
        let data_failover_workflows = Self::read_active_collection::<data_state::FailoverWorkflow>(
            &platform_root.join("data/failover_workflows.json"),
        )
        .unwrap_or_default();
        let data_migrations = Self::read_active_collection::<data_state::DataMigrationJob>(
            &platform_root.join("data/migrations.json"),
        )
        .unwrap_or_default();

        let mut region_rollups = BTreeMap::<String, RegionAccumulator>::new();
        let mut cell_rollups = BTreeMap::<String, CellAccumulator>::new();

        for cell in cell_directory {
            let region_id = cell.region.region_id.clone();
            let region_name = cell.region.region_name.clone();
            let metrics = summarize_cell_participants(&cell.participants);
            let cell_ready = metrics.is_ready();

            cell_rollups.insert(
                cell.cell_id.clone(),
                CellAccumulator {
                    cell_name: cell.cell_name.clone(),
                    region_id: region_id.clone(),
                    region_name: region_name.clone(),
                    participant_count: metrics.participant_count,
                    serving_participants: metrics.serving_participants,
                    draining_participants: metrics.draining_participants,
                    degraded_participants: metrics.degraded_participants,
                    stale_participants: metrics.stale_participants,
                    expired_participants: metrics.expired_participants,
                    takeover_pending: metrics.takeover_pending,
                    takeover_acknowledged: metrics.takeover_acknowledged,
                    incident_total: 0,
                    incident_open: 0,
                    incident_status_counts: BTreeMap::new(),
                    incident_severity_counts: BTreeMap::new(),
                },
            );

            let region_entry =
                ensure_region_accumulator(&mut region_rollups, &region_id, Some(&region_name));
            region_entry.total_cells = region_entry.total_cells.saturating_add(1);
            region_entry.participant_count = region_entry
                .participant_count
                .saturating_add(metrics.participant_count);
            if cell_ready {
                region_entry.ready_cells = region_entry.ready_cells.saturating_add(1);
            } else {
                region_entry.degraded_cells = region_entry.degraded_cells.saturating_add(1);
            }
        }

        for reconciliation in reconciliations {
            let Some(region_id) = normalized_non_empty(&reconciliation.region) else {
                continue;
            };
            let region_entry = ensure_region_accumulator(&mut region_rollups, &region_id, None);
            region_entry.reconciliation_available = true;
            region_entry.fully_reconciled = reconciliation.fully_reconciled;
            region_entry.healthy_votes = Some(reconciliation.healthy_votes);
            region_entry.majority_threshold = Some(reconciliation.majority_threshold);
            region_entry.uncommitted_entries = reconciliation.uncommitted_entries;
            region_entry.lagging_nodes = reconciliation.lagging_nodes.len();
        }

        let critical_dependencies_down = dependencies
            .iter()
            .filter(|dependency| {
                dependency.critical && status_matches(&dependency.status, &["down"])
            })
            .count();
        let critical_dependencies_degraded = dependencies
            .iter()
            .filter(|dependency| {
                dependency.critical && status_matches(&dependency.status, &["degraded"])
            })
            .count();

        let ha_failovers_in_progress = ha_failovers
            .iter()
            .filter(|record| operation_state_is_active(&record.state))
            .count();
        let ha_failovers_failed = ha_failovers
            .iter()
            .filter(|record| operation_state_is_failed(&record.state))
            .count();
        let ha_repair_workflows_active = ha_repair_workflows
            .iter()
            .filter(|workflow| workflow_phase_is_active(&workflow.phase))
            .count();
        let ha_repair_workflows_failed = ha_repair_workflows
            .iter()
            .filter(|workflow| workflow_phase_is_failed(&workflow.phase))
            .count();
        let lifecycle_dead_letters_pending = dead_letters
            .iter()
            .filter(|record| !record.replayed)
            .count();
        let lifecycle_repair_jobs_active = lifecycle_repair_jobs.active;
        let lifecycle_repair_jobs_failed = lifecycle_repair_jobs.failed;
        let data_failovers_active = data_failovers
            .iter()
            .filter(|record| operation_state_is_active(&record.state))
            .count();
        let data_failovers_failed = data_failovers
            .iter()
            .filter(|record| operation_state_is_failed(&record.state))
            .count();
        let data_migrations_active = data_migrations
            .iter()
            .filter(|record| operation_state_is_active(&record.state))
            .count();
        let data_migrations_failed = data_migrations
            .iter()
            .filter(|record| operation_state_is_failed(&record.state))
            .count();

        for workflow in data_failover_workflows {
            let Some(region_id) = normalized_non_empty(&workflow.state.target_region) else {
                continue;
            };
            let region_entry = ensure_region_accumulator(&mut region_rollups, &region_id, None);
            if workflow_phase_is_active(&workflow.phase) {
                region_entry.data_failovers_active =
                    region_entry.data_failovers_active.saturating_add(1);
            }
            if workflow_phase_is_failed(&workflow.phase) {
                region_entry.data_failovers_failed =
                    region_entry.data_failovers_failed.saturating_add(1);
            }
        }

        for migration in data_migrations {
            let mut regions = HashSet::<String>::new();
            if let Some(source_region) = migration.source_region.as_deref()
                && let Some(region_id) = normalized_non_empty(source_region)
            {
                regions.insert(region_id);
            }
            if let Some(target_region) = migration.target_region.as_deref()
                && let Some(region_id) = normalized_non_empty(target_region)
            {
                regions.insert(region_id);
            }

            for region_id in regions {
                let region_entry = ensure_region_accumulator(&mut region_rollups, &region_id, None);
                if operation_state_is_active(&migration.state) {
                    region_entry.data_migrations_active =
                        region_entry.data_migrations_active.saturating_add(1);
                }
                if operation_state_is_failed(&migration.state) {
                    region_entry.data_migrations_failed =
                        region_entry.data_migrations_failed.saturating_add(1);
                }
            }
        }

        let mut incident_total = 0_usize;
        let mut incident_open = 0_usize;
        let mut incident_status_counts = BTreeMap::new();
        let mut incident_severity_counts = BTreeMap::new();
        let mut attributed_region_incidents = 0_usize;
        let mut attributed_cell_incidents = 0_usize;
        let mut unattributed_incidents = 0_usize;

        for incident in &incidents {
            tally_incident(
                &mut incident_total,
                &mut incident_open,
                &mut incident_status_counts,
                &mut incident_severity_counts,
                incident,
            );

            let region_hint = incident_region_scope(incident);
            let cell_hint = incident_cell_scope(incident);
            let mut cell_region = None::<(String, String)>;

            if let Some(cell_id) = cell_hint.as_deref()
                && let Some(cell_entry) = cell_rollups.get_mut(cell_id)
            {
                tally_incident(
                    &mut cell_entry.incident_total,
                    &mut cell_entry.incident_open,
                    &mut cell_entry.incident_status_counts,
                    &mut cell_entry.incident_severity_counts,
                    incident,
                );
                cell_region = Some((cell_entry.region_id.clone(), cell_entry.region_name.clone()));
                attributed_cell_incidents = attributed_cell_incidents.saturating_add(1);
            }

            let region_key = region_hint
                .clone()
                .or_else(|| cell_region.as_ref().map(|(region_id, _)| region_id.clone()));
            if let Some(region_id) = region_key {
                let region_name = cell_region
                    .as_ref()
                    .filter(|(candidate_id, _)| *candidate_id == region_id)
                    .map(|(_, region_name)| region_name.as_str());
                let region_entry =
                    ensure_region_accumulator(&mut region_rollups, &region_id, region_name);
                tally_incident(
                    &mut region_entry.incident_total,
                    &mut region_entry.incident_open,
                    &mut region_entry.incident_status_counts,
                    &mut region_entry.incident_severity_counts,
                    incident,
                );
                attributed_region_incidents = attributed_region_incidents.saturating_add(1);
            } else {
                unattributed_incidents = unattributed_incidents.saturating_add(1);
            }
        }

        let cells = cell_rollups
            .into_iter()
            .map(|(cell_id, cell)| {
                let ready = cell_is_ready(&cell);
                let backlog_health = CellBacklogHealthRollup {
                    attention_items: cell
                        .stale_participants
                        .saturating_add(cell.takeover_pending)
                        .saturating_add(cell.takeover_acknowledged),
                    critical_items: cell.expired_participants,
                    stale_participants: cell.stale_participants,
                    expired_participants: cell.expired_participants,
                    takeover_pending: cell.takeover_pending,
                    takeover_acknowledged: cell.takeover_acknowledged,
                };

                CellFleetOpsRollup {
                    cell_id,
                    cell_name: cell.cell_name,
                    region_id: cell.region_id,
                    region_name: cell.region_name,
                    ha_readiness: CellHaReadinessRollup {
                        participant_count: cell.participant_count,
                        serving_participants: cell.serving_participants,
                        draining_participants: cell.draining_participants,
                        degraded_participants: cell.degraded_participants,
                        stale_participants: cell.stale_participants,
                        expired_participants: cell.expired_participants,
                        ready,
                    },
                    incident_state: ScopedIncidentRollup {
                        total_incidents: cell.incident_total,
                        open_incidents: cell.incident_open,
                        status_counts: cell.incident_status_counts,
                        severity_counts: cell.incident_severity_counts,
                    },
                    backlog_health,
                }
            })
            .collect::<Vec<_>>();

        let regions = region_rollups
            .into_iter()
            .map(|(region_id, region)| {
                let ready = region.total_cells > 0
                    && region.degraded_cells == 0
                    && region.reconciliation_available
                    && region.fully_reconciled
                    && region.uncommitted_entries == 0
                    && region.lagging_nodes == 0;
                let region_name = if region.region_name.is_empty() {
                    region_id.clone()
                } else {
                    region.region_name
                };
                let backlog_health = RegionBacklogHealthRollup {
                    attention_items: u64_to_usize_saturating(region.uncommitted_entries)
                        .saturating_add(region.lagging_nodes)
                        .saturating_add(region.data_migrations_active)
                        .saturating_add(region.data_failovers_active),
                    critical_items: usize::from(
                        region.reconciliation_available && !region.fully_reconciled,
                    )
                    .saturating_add(region.data_migrations_failed)
                    .saturating_add(region.data_failovers_failed),
                    uncommitted_entries: region.uncommitted_entries,
                    lagging_nodes: region.lagging_nodes,
                    data_migrations_active: region.data_migrations_active,
                    data_migrations_failed: region.data_migrations_failed,
                    data_failovers_active: region.data_failovers_active,
                    data_failovers_failed: region.data_failovers_failed,
                };

                RegionFleetOpsRollup {
                    region_id,
                    region_name,
                    ha_readiness: RegionHaReadinessRollup {
                        total_cells: region.total_cells,
                        ready_cells: region.ready_cells,
                        degraded_cells: region.degraded_cells,
                        participant_count: region.participant_count,
                        reconciliation_available: region.reconciliation_available,
                        fully_reconciled: region.fully_reconciled,
                        healthy_votes: region.healthy_votes,
                        majority_threshold: region.majority_threshold,
                        uncommitted_entries: region.uncommitted_entries,
                        lagging_nodes: region.lagging_nodes,
                        ready,
                    },
                    incident_state: ScopedIncidentRollup {
                        total_incidents: region.incident_total,
                        open_incidents: region.incident_open,
                        status_counts: region.incident_status_counts,
                        severity_counts: region.incident_severity_counts,
                    },
                    backlog_health,
                }
            })
            .collect::<Vec<_>>();

        let ready_regions = regions
            .iter()
            .filter(|region| region.ha_readiness.ready)
            .count();
        let regions_missing_reconciliation = regions
            .iter()
            .filter(|region| !region.ha_readiness.reconciliation_available)
            .count();
        let unreconciled_regions = regions
            .iter()
            .filter(|region| {
                region.ha_readiness.reconciliation_available
                    && (!region.ha_readiness.fully_reconciled
                        || region.ha_readiness.uncommitted_entries > 0
                        || region.ha_readiness.lagging_nodes > 0)
            })
            .count();
        let ready_cells = cells.iter().filter(|cell| cell.ha_readiness.ready).count();

        Ok(FleetOpsRollups {
            state_root: platform_root.display().to_string(),
            generated_at,
            ha_readiness: FleetOpsHaReadinessRollup {
                total_regions: regions.len(),
                ready_regions,
                degraded_regions: regions.len().saturating_sub(ready_regions),
                regions_missing_reconciliation,
                unreconciled_regions,
                total_cells: cells.len(),
                ready_cells,
                degraded_cells: cells.len().saturating_sub(ready_cells),
                critical_dependencies_down,
                critical_dependencies_degraded,
            },
            incident_state: FleetOpsIncidentStateRollup {
                total_incidents: incident_total,
                open_incidents: incident_open,
                resolved_incidents: incident_total.saturating_sub(incident_open),
                status_counts: incident_status_counts,
                severity_counts: incident_severity_counts,
                attributed_region_incidents,
                attributed_cell_incidents,
                unattributed_incidents,
            },
            backlog_health: FleetOpsBacklogHealthRollup {
                attention_items: ha_failovers_in_progress
                    .saturating_add(ha_repair_workflows_active)
                    .saturating_add(lifecycle_dead_letters_pending)
                    .saturating_add(lifecycle_repair_jobs_active)
                    .saturating_add(data_failovers_active)
                    .saturating_add(data_migrations_active),
                critical_items: ha_failovers_failed
                    .saturating_add(ha_repair_workflows_failed)
                    .saturating_add(lifecycle_repair_jobs_failed)
                    .saturating_add(data_failovers_failed)
                    .saturating_add(data_migrations_failed),
                ha_failovers_in_progress,
                ha_failovers_failed,
                ha_repair_workflows_active,
                ha_repair_workflows_failed,
                lifecycle_dead_letters_pending,
                lifecycle_repair_jobs_active,
                lifecycle_repair_jobs_failed,
                data_failovers_active,
                data_failovers_failed,
                data_migrations_active,
                data_migrations_failed,
            },
            regions,
            cells,
        })
    }

    async fn create_alert_rule(
        &self,
        request: CreateAlertRuleRequest,
    ) -> Result<http::Response<ApiBody>> {
        let id = AlertRuleId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate alert rule id")
                .with_detail(error.to_string())
        })?;
        let record = AlertRule {
            id: id.clone(),
            name: request.name,
            expression: request.expression,
            severity: request.severity,
            enabled: true,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.alert_rules.create(id.as_str(), record.clone()).await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_activity(
        &self,
        request: CreateActivityRequest,
    ) -> Result<http::Response<ApiBody>> {
        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate activity id")
                .with_detail(error.to_string())
        })?;
        let entry = ActivityEntry {
            id: id.clone(),
            category: request.category,
            summary: request.summary,
            correlation_id: request.correlation_id,
            created_at: OffsetDateTime::now_utc(),
        };
        self.activity.create(id.as_str(), entry.clone()).await?;
        json_response(StatusCode::CREATED, &entry)
    }

    async fn create_otlp_exporter(
        &self,
        request: CreateOtlpExporterRequest,
    ) -> Result<http::Response<ApiBody>> {
        let signal = normalize_signal(&request.signal)?;
        if !request.endpoint.starts_with("http://") && !request.endpoint.starts_with("https://") {
            return Err(PlatformError::invalid(
                "OTLP endpoint must start with http:// or https://",
            ));
        }
        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate exporter id")
                .with_detail(error.to_string())
        })?;
        let record = OtlpExporter {
            id: id.clone(),
            signal,
            endpoint: request.endpoint,
            insecure: request.insecure,
            headers: request.headers,
            enabled: true,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.otlp_exporters
            .create(id.as_str(), record.clone())
            .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_slo(&self, request: CreateSloRequest) -> Result<http::Response<ApiBody>> {
        if request.name.trim().is_empty() || request.sli_kind.trim().is_empty() {
            return Err(PlatformError::invalid("name and sli_kind may not be empty"));
        }
        if request.target_success_per_million == 0 || request.target_success_per_million > 1_000_000
        {
            return Err(PlatformError::invalid(
                "target_success_per_million must be between 1 and 1000000",
            ));
        }
        if request.window_minutes == 0 {
            return Err(PlatformError::invalid(
                "window_minutes must be greater than 0",
            ));
        }
        let alert_route_id = request
            .alert_route_id
            .map(|raw| {
                RouteId::parse(raw).map_err(|error| {
                    PlatformError::invalid("invalid alert_route_id").with_detail(error.to_string())
                })
            })
            .transpose()?;
        let id = AlertRuleId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate slo id").with_detail(error.to_string())
        })?;
        let record = SloDefinition {
            id: id.clone(),
            name: request.name,
            sli_kind: request.sli_kind.to_ascii_lowercase(),
            target_success_per_million: request.target_success_per_million,
            window_minutes: request.window_minutes,
            alert_route_id,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.slos.create(id.as_str(), record.clone()).await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_alert_route(
        &self,
        request: CreateAlertRouteRequest,
    ) -> Result<http::Response<ApiBody>> {
        if request.name.trim().is_empty() || request.destination.trim().is_empty() {
            return Err(PlatformError::invalid(
                "name and destination may not be empty",
            ));
        }
        let id = RouteId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate alert route id")
                .with_detail(error.to_string())
        })?;
        let record = AlertRoutePolicy {
            id: id.clone(),
            name: request.name,
            destination: request.destination,
            severity_filter: request
                .severity_filter
                .into_iter()
                .map(|item| item.to_ascii_lowercase())
                .collect(),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.alert_routes
            .create(id.as_str(), record.clone())
            .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_slow_path(
        &self,
        request: CreateSlowPathRequest,
    ) -> Result<http::Response<ApiBody>> {
        if request.category.trim().is_empty() || request.resource.trim().is_empty() {
            return Err(PlatformError::invalid(
                "category and resource may not be empty",
            ));
        }
        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate slow path id")
                .with_detail(error.to_string())
        })?;
        let record = SlowPathEntry {
            id: id.clone(),
            category: request.category.to_ascii_lowercase(),
            resource: request.resource,
            latency_ms: request.latency_ms,
            exemplar_trace_id: request.exemplar_trace_id,
            observed_at: OffsetDateTime::now_utc(),
        };
        self.slow_paths.create(id.as_str(), record.clone()).await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_otlp_dispatch(
        &self,
        request: CreateOtlpDispatchRequest,
    ) -> Result<http::Response<ApiBody>> {
        let exporter_id = AuditId::parse(request.exporter_id).map_err(|error| {
            PlatformError::invalid("invalid exporter_id").with_detail(error.to_string())
        })?;
        let exporter = self
            .otlp_exporters
            .get(exporter_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("OTLP exporter does not exist"))?;
        if !exporter.value.enabled {
            return Err(PlatformError::conflict("OTLP exporter is disabled"));
        }

        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate OTLP dispatch id")
                .with_detail(error.to_string())
        })?;
        let (status, error) = if exporter.value.endpoint.starts_with("http://")
            || exporter.value.endpoint.starts_with("https://")
        {
            (String::from("sent"), None)
        } else {
            (
                String::from("failed"),
                Some(String::from("exporter endpoint has unsupported scheme")),
            )
        };
        let latency_ms = ((request.payload_bytes / 32_768) + 5).clamp(1, 5_000);
        let attempt = OtlpDispatchAttempt {
            id: id.clone(),
            exporter_id,
            signal: exporter.value.signal,
            batch_items: request.batch_items.max(1),
            payload_bytes: request.payload_bytes,
            status,
            latency_ms,
            error,
            created_at: OffsetDateTime::now_utc(),
        };
        self.otlp_dispatch
            .create(id.as_str(), attempt.clone())
            .await?;
        json_response(StatusCode::CREATED, &attempt)
    }

    async fn error_budgets(&self) -> Result<Vec<ErrorBudgetSnapshot>> {
        let slos = self
            .slos
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let activity = self
            .activity
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let slow_paths = self
            .slow_paths
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        Ok(compute_error_budgets(&slos, &activity, &slow_paths))
    }

    async fn exemplars(&self) -> Result<Vec<serde_json::Value>> {
        let activity = self
            .activity
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let slow_paths = self
            .slow_paths
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();

        let mut exemplars = Vec::new();
        for slow_path in slow_paths {
            let related_activity = slow_path.exemplar_trace_id.as_ref().and_then(|trace_id| {
                activity.iter().find(|entry| {
                    entry
                        .correlation_id
                        .as_ref()
                        .is_some_and(|value| value == trace_id)
                })
            });
            exemplars.push(serde_json::json!({
                "slow_path_id": slow_path.id,
                "category": slow_path.category,
                "latency_ms": slow_path.latency_ms,
                "exemplar_trace_id": slow_path.exemplar_trace_id,
                "activity_id": related_activity.map(|entry| entry.id.to_string()),
                "activity_summary": related_activity.map(|entry| entry.summary.clone()),
            }));
        }
        Ok(exemplars)
    }

    async fn evaluate_incidents(
        &self,
        request: EvaluateIncidentsRequest,
    ) -> Result<http::Response<ApiBody>> {
        let include_alert_rules = request.include_alert_rules.unwrap_or(true);
        let include_slos = request.include_slos.unwrap_or(true);
        let routes = self
            .alert_routes
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        let slow_paths = self
            .slow_paths
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        let existing_open_incidents = self
            .incidents
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted && value.value.status == "open")
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();

        let mut incidents = Vec::new();
        let mut evaluated_rules = 0_usize;
        let mut evaluated_slos = 0_usize;

        if include_alert_rules {
            let alert_rules = self
                .alert_rules
                .list()
                .await?
                .into_iter()
                .filter(|(_, value)| !value.deleted)
                .map(|(_, value)| value.value)
                .collect::<Vec<_>>();
            for rule in alert_rules.into_iter().filter(|rule| rule.enabled) {
                evaluated_rules = evaluated_rules.saturating_add(1);
                if !rule_expression_triggered(&rule.expression, &slow_paths)? {
                    continue;
                }
                let source_id = rule.id.to_string();
                if existing_open_incidents.iter().any(|incident| {
                    incident.source_kind == "alert_rule" && incident.source_id == source_id
                }) {
                    continue;
                }
                let (route_id, destination) = pick_alert_route(&routes, &rule.severity, None);
                let id = AuditId::generate().map_err(|error| {
                    PlatformError::unavailable("failed to allocate incident id")
                        .with_detail(error.to_string())
                })?;
                let incident = ObserveIncident {
                    id: id.clone(),
                    source_kind: String::from("alert_rule"),
                    source_id,
                    severity: normalize_severity(&rule.severity)?,
                    summary: format!("alert rule `{}` triggered", rule.name),
                    route_id,
                    destination,
                    status: String::from("open"),
                    correlation_id: None,
                    created_at: OffsetDateTime::now_utc(),
                    resolved_at: None,
                    metadata: ResourceMetadata::new(
                        OwnershipScope::Platform,
                        Some(id.to_string()),
                        sha256_hex(id.as_str().as_bytes()),
                    ),
                };
                self.incidents.create(id.as_str(), incident.clone()).await?;
                incidents.push(incident);
            }
        }

        if include_slos {
            let activity = self
                .activity
                .list()
                .await?
                .into_iter()
                .filter(|(_, value)| !value.deleted)
                .map(|(_, value)| value.value)
                .collect::<Vec<_>>();
            let slos = self
                .slos
                .list()
                .await?
                .into_iter()
                .filter(|(_, value)| !value.deleted)
                .map(|(_, value)| value.value)
                .collect::<Vec<_>>();
            let budgets = compute_error_budgets(&slos, &activity, &slow_paths);
            for budget in budgets {
                evaluated_slos = evaluated_slos.saturating_add(1);
                if budget.measured_success_per_million >= budget.success_target_per_million {
                    continue;
                }
                let source_id = budget.slo_id.to_string();
                if existing_open_incidents.iter().any(|incident| {
                    incident.source_kind == "slo" && incident.source_id == source_id
                }) {
                    continue;
                }
                let deficit = budget
                    .success_target_per_million
                    .saturating_sub(budget.measured_success_per_million);
                let severity = if deficit >= 100_000 {
                    "critical"
                } else if deficit >= 25_000 {
                    "high"
                } else {
                    "medium"
                };
                let preferred_route = slos
                    .iter()
                    .find(|slo| slo.id == budget.slo_id)
                    .and_then(|slo| slo.alert_route_id.clone());
                let (route_id, destination) =
                    pick_alert_route(&routes, severity, preferred_route.as_ref());
                let id = AuditId::generate().map_err(|error| {
                    PlatformError::unavailable("failed to allocate incident id")
                        .with_detail(error.to_string())
                })?;
                let incident = ObserveIncident {
                    id: id.clone(),
                    source_kind: String::from("slo"),
                    source_id,
                    severity: String::from(severity),
                    summary: format!(
                        "SLO `{}` breach: target={} measured={}",
                        budget.slo_name,
                        budget.success_target_per_million,
                        budget.measured_success_per_million
                    ),
                    route_id,
                    destination,
                    status: String::from("open"),
                    correlation_id: None,
                    created_at: OffsetDateTime::now_utc(),
                    resolved_at: None,
                    metadata: ResourceMetadata::new(
                        OwnershipScope::Platform,
                        Some(id.to_string()),
                        sha256_hex(id.as_str().as_bytes()),
                    ),
                };
                self.incidents.create(id.as_str(), incident.clone()).await?;
                incidents.push(incident);
            }
        }

        let report = IncidentEvaluationReport {
            evaluated_rules,
            evaluated_slos,
            incidents_created: incidents.len(),
            incidents,
        };
        json_response(StatusCode::OK, &report)
    }

    async fn resolve_incident(
        &self,
        incident_id: &str,
        request: ResolveIncidentRequest,
    ) -> Result<http::Response<ApiBody>> {
        let incident_id = AuditId::parse(incident_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid incident_id").with_detail(error.to_string())
        })?;
        let stored = self
            .incidents
            .get(incident_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("incident does not exist"))?;
        if stored.value.status == "resolved" {
            return json_response(StatusCode::OK, &stored.value);
        }
        let mut incident = stored.value;
        incident.status = String::from("resolved");
        incident.resolved_at = Some(OffsetDateTime::now_utc());
        if let Some(reason) = request.reason {
            let trimmed = reason.trim();
            if !trimmed.is_empty() {
                incident.correlation_id = Some(sha256_hex(trimmed.as_bytes()));
            }
        }
        incident
            .metadata
            .touch(sha256_hex(incident.id.as_str().as_bytes()));
        self.incidents
            .upsert(incident.id.as_str(), incident.clone(), Some(stored.version))
            .await?;
        json_response(StatusCode::OK, &incident)
    }
}

impl HttpService for ObserveService {
    fn name(&self) -> &'static str {
        "observe"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/observe")];
        ROUTE_CLAIMS
    }

    fn handle<'a>(
        &'a self,
        request: Request<uhost_runtime::RequestBody>,
        _context: RequestContext,
    ) -> ResponseFuture<'a> {
        Box::pin(async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let segments = path_segments(&path);

            match (method, segments.as_slice()) {
                (Method::GET, ["observe"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                        "signals": ["logs", "metrics", "traces", "profiles"],
                    }),
                )
                .map(Some),
                (Method::GET, ["observe", "summary"]) => {
                    let summary = self.observe_summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["observe", "fleet-ops-rollups"]) => {
                    let summary = self.fleet_ops_rollups().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["observe", "alert-rules"]) => {
                    let values = self
                        .alert_rules
                        .list()
                        .await?
                        .into_iter()
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["observe", "alert-rules"]) => {
                    let body: CreateAlertRuleRequest = parse_json(request).await?;
                    self.create_alert_rule(body).await.map(Some)
                }
                (Method::GET, ["observe", "activity"]) => {
                    let values = self
                        .activity
                        .list()
                        .await?
                        .into_iter()
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["observe", "activity"]) => {
                    let body: CreateActivityRequest = parse_json(request).await?;
                    self.create_activity(body).await.map(Some)
                }
                (Method::GET, ["observe", "otlp-exporters"]) => {
                    let values = self
                        .otlp_exporters
                        .list()
                        .await?
                        .into_iter()
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["observe", "otlp-exporters"]) => {
                    let body: CreateOtlpExporterRequest = parse_json(request).await?;
                    self.create_otlp_exporter(body).await.map(Some)
                }
                (Method::GET, ["observe", "otlp-dispatch"]) => {
                    let values = self
                        .otlp_dispatch
                        .list()
                        .await?
                        .into_iter()
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["observe", "otlp-dispatch"]) => {
                    let body: CreateOtlpDispatchRequest = parse_json(request).await?;
                    self.create_otlp_dispatch(body).await.map(Some)
                }
                (Method::GET, ["observe", "slos"]) => {
                    let values = self
                        .slos
                        .list()
                        .await?
                        .into_iter()
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["observe", "slos"]) => {
                    let body: CreateSloRequest = parse_json(request).await?;
                    self.create_slo(body).await.map(Some)
                }
                (Method::GET, ["observe", "error-budgets"]) => {
                    let values = self.error_budgets().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["observe", "node-health"]) => {
                    let summary = self.node_health_summary();
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["observe", "alert-routes"]) => {
                    let values = self
                        .alert_routes
                        .list()
                        .await?
                        .into_iter()
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["observe", "alert-routes"]) => {
                    let body: CreateAlertRouteRequest = parse_json(request).await?;
                    self.create_alert_route(body).await.map(Some)
                }
                (Method::GET, ["observe", "slow-paths"]) => {
                    let values = self
                        .slow_paths
                        .list()
                        .await?
                        .into_iter()
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["observe", "slow-paths"]) => {
                    let body: CreateSlowPathRequest = parse_json(request).await?;
                    self.create_slow_path(body).await.map(Some)
                }
                (Method::GET, ["observe", "exemplars"]) => {
                    let values = self.exemplars().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["observe", "incidents"]) => {
                    let values = self
                        .incidents
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["observe", "incidents", "evaluate"]) => {
                    let body: EvaluateIncidentsRequest = parse_json(request).await?;
                    self.evaluate_incidents(body).await.map(Some)
                }
                (Method::POST, ["observe", "incidents", incident_id, "resolve"]) => {
                    let body: ResolveIncidentRequest = parse_json(request).await?;
                    self.resolve_incident(incident_id, body).await.map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn normalize_signal(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "logs" | "metrics" | "traces" | "profiles" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "signal must be one of logs/metrics/traces/profiles",
        )),
    }
}

fn normalize_severity(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "low" | "medium" | "high" | "critical" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "severity must be one of low/medium/high/critical",
        )),
    }
}

fn category_matches(actual: &str, expected: &str) -> bool {
    actual.trim().eq_ignore_ascii_case(expected.trim())
}

fn compute_error_budgets(
    slos: &[SloDefinition],
    activity: &[ActivityEntry],
    slow_paths: &[SlowPathEntry],
) -> Vec<ErrorBudgetSnapshot> {
    let mut snapshots = Vec::with_capacity(slos.len());
    for slo in slos {
        let total = activity
            .iter()
            .filter(|entry| category_matches(&entry.category, &slo.sli_kind))
            .count()
            .max(1) as u64;
        let bad = slow_paths
            .iter()
            .filter(|entry| category_matches(&entry.category, &slo.sli_kind))
            .count() as u64;
        let degraded = (bad * 1_000_000_u64 / total).min(1_000_000) as u32;
        let measured_success_per_million = 1_000_000_u32.saturating_sub(degraded);
        snapshots.push(ErrorBudgetSnapshot {
            slo_id: slo.id.clone(),
            slo_name: slo.name.clone(),
            success_target_per_million: slo.target_success_per_million,
            measured_success_per_million,
            budget_remaining_per_million: measured_success_per_million
                .saturating_sub(slo.target_success_per_million),
            window_minutes: slo.window_minutes,
        });
    }
    snapshots
}

fn pick_alert_route(
    routes: &[AlertRoutePolicy],
    severity: &str,
    preferred_route: Option<&RouteId>,
) -> (Option<RouteId>, Option<String>) {
    if let Some(preferred) = preferred_route
        && let Some(route) = routes.iter().find(|route| &route.id == preferred)
    {
        return (Some(route.id.clone()), Some(route.destination.clone()));
    }
    let normalized = severity.trim();
    let matched = routes.iter().find(|route| {
        route.severity_filter.is_empty()
            || route
                .severity_filter
                .iter()
                .any(|entry| entry.trim().eq_ignore_ascii_case(normalized))
    });
    (
        matched.map(|route| route.id.clone()),
        matched.map(|route| route.destination.clone()),
    )
}

fn rule_expression_triggered(expression: &str, slow_paths: &[SlowPathEntry]) -> Result<bool> {
    let normalized = expression.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(
            "alert rule expression may not be empty",
        ));
    }
    if let Some(threshold) = normalized.strip_prefix("latency_ms>") {
        let threshold = threshold.parse::<u64>().map_err(|error| {
            PlatformError::invalid("invalid latency_ms threshold in alert expression")
                .with_detail(error.to_string())
        })?;
        return Ok(slow_paths.iter().any(|entry| entry.latency_ms > threshold));
    }
    if let Some(threshold) = normalized.strip_prefix("slow_path_count>") {
        let threshold = threshold.parse::<usize>().map_err(|error| {
            PlatformError::invalid("invalid slow_path_count threshold in alert expression")
                .with_detail(error.to_string())
        })?;
        return Ok(slow_paths.len() > threshold);
    }
    if let Some(category) = normalized.strip_prefix("category:") {
        let category = category.trim();
        if category.is_empty() {
            return Err(PlatformError::invalid(
                "category expression requires non-empty category",
            ));
        }
        return Ok(slow_paths
            .iter()
            .any(|entry| category_matches(&entry.category, category)));
    }
    Ok(false)
}

fn active_records<T>(records: Vec<(String, StoredDocument<T>)>) -> Vec<T> {
    records
        .into_iter()
        .filter(|(_, stored)| !stored.deleted)
        .map(|(_, stored)| stored.value)
        .collect()
}

fn ensure_region_accumulator<'a>(
    regions: &'a mut BTreeMap<String, RegionAccumulator>,
    region_id: &str,
    region_name: Option<&str>,
) -> &'a mut RegionAccumulator {
    let entry = regions.entry(region_id.to_owned()).or_default();
    if entry.region_name.is_empty()
        && let Some(region_name) = region_name.and_then(normalized_non_empty)
    {
        entry.region_name = region_name;
    }
    entry
}

fn summarize_cell_participants(participants: &[uhost_store::CellParticipantRecord]) -> CellMetrics {
    let mut metrics = CellMetrics {
        participant_count: participants.len(),
        ..CellMetrics::default()
    };

    for participant in participants {
        let Some(state) = participant.state.as_ref() else {
            metrics.degraded_participants = metrics.degraded_participants.saturating_add(1);
            continue;
        };

        if participant_is_serving(state) {
            metrics.serving_participants = metrics.serving_participants.saturating_add(1);
        }
        if participant_is_draining(state) {
            metrics.draining_participants = metrics.draining_participants.saturating_add(1);
        }
        if participant_is_degraded(state) {
            metrics.degraded_participants = metrics.degraded_participants.saturating_add(1);
        }
        match state.lease.freshness {
            LeaseFreshness::Fresh => {}
            LeaseFreshness::Stale => {
                metrics.stale_participants = metrics.stale_participants.saturating_add(1);
            }
            LeaseFreshness::Expired => {
                metrics.expired_participants = metrics.expired_participants.saturating_add(1);
            }
        }
        match state.drain_phase {
            CellParticipantDrainPhase::Serving => {}
            CellParticipantDrainPhase::TakeoverPending => {
                metrics.takeover_pending = metrics.takeover_pending.saturating_add(1);
            }
            CellParticipantDrainPhase::TakeoverAcknowledged => {
                metrics.takeover_acknowledged = metrics.takeover_acknowledged.saturating_add(1);
            }
        }
    }

    metrics
}

fn participant_is_serving(state: &CellParticipantState) -> bool {
    state.readiness == LeaseReadiness::Ready
        && state.published_drain_intent() == LeaseDrainIntent::Serving
        && matches!(state.lease.freshness, LeaseFreshness::Fresh)
        && state.degraded_reason.is_none()
}

fn participant_is_draining(state: &CellParticipantState) -> bool {
    state.published_drain_intent() == LeaseDrainIntent::Draining
        || !matches!(state.drain_phase, CellParticipantDrainPhase::Serving)
}

fn participant_is_degraded(state: &CellParticipantState) -> bool {
    state.readiness != LeaseReadiness::Ready
        || !matches!(state.lease.freshness, LeaseFreshness::Fresh)
        || participant_is_draining(state)
        || state.degraded_reason.is_some()
}

fn cell_is_ready(cell: &CellAccumulator) -> bool {
    cell.participant_count > 0 && cell.degraded_participants == 0 && cell.serving_participants > 0
}

impl CellMetrics {
    fn is_ready(&self) -> bool {
        self.participant_count > 0
            && self.degraded_participants == 0
            && self.serving_participants > 0
    }
}

fn tally_incident(
    total: &mut usize,
    open: &mut usize,
    status_counts: &mut BTreeMap<String, usize>,
    severity_counts: &mut BTreeMap<String, usize>,
    incident: &ObserveIncident,
) {
    *total = total.saturating_add(1);
    if incident_status_is_open(&incident.status) {
        *open = open.saturating_add(1);
    }

    let status = incident.status.trim().to_ascii_lowercase();
    *status_counts.entry(status).or_default() += 1;

    let severity = incident.severity.trim().to_ascii_lowercase();
    *severity_counts.entry(severity).or_default() += 1;
}

fn incident_status_is_open(status: &str) -> bool {
    !status_matches(status, &["resolved", "closed", "completed"])
}

fn incident_region_scope(incident: &ObserveIncident) -> Option<String> {
    metadata_scope_value(
        &incident.metadata,
        &[
            "region",
            "region_id",
            "ha.region",
            "uhost.region",
            "target_region",
            "source_region",
            "primary_region",
        ],
    )
}

fn incident_cell_scope(incident: &ObserveIncident) -> Option<String> {
    metadata_scope_value(
        &incident.metadata,
        &[
            "cell",
            "cell_id",
            "ha.cell",
            "ha.cell_id",
            "runtime.cell",
            "runtime.cell_id",
            "uhost.cell",
        ],
    )
}

fn metadata_scope_value(metadata: &ResourceMetadata, keys: &[&str]) -> Option<String> {
    for key in keys {
        let normalized = key.to_ascii_lowercase();
        if let Some(value) = metadata
            .annotations
            .get(&normalized)
            .and_then(|value| normalized_non_empty(value))
        {
            return Some(value);
        }
        if let Some(value) = metadata
            .labels
            .get(&normalized)
            .and_then(|value| normalized_non_empty(value))
        {
            return Some(value);
        }
    }
    None
}

fn normalized_non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn status_matches(value: &str, expected: &[&str]) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    expected.iter().any(|candidate| normalized == *candidate)
}

fn operation_state_is_active(state: &str) -> bool {
    status_matches(
        state,
        &[
            "pending",
            "requested",
            "queued",
            "running",
            "in_progress",
            "starting",
            "pending_confirmation",
        ],
    )
}

fn operation_state_is_failed(state: &str) -> bool {
    status_matches(
        state,
        &["failed", "error", "errored", "aborted", "cancelled"],
    )
}

fn repair_job_state_is_active(state: &str) -> bool {
    !status_matches(state, &["completed", "failed"])
}

fn repair_job_state_is_failed(state: &str) -> bool {
    status_matches(state, &["failed"])
}

fn workflow_phase_is_active(phase: &WorkflowPhase) -> bool {
    matches!(
        phase,
        WorkflowPhase::Pending | WorkflowPhase::Running | WorkflowPhase::Paused
    )
}

fn workflow_phase_is_failed(phase: &WorkflowPhase) -> bool {
    matches!(phase, WorkflowPhase::Failed)
}

fn u64_to_usize_saturating(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tempfile::tempdir;
    use uhost_store::{
        CellDirectoryRecord, CellParticipantLeaseState, CellParticipantRecord,
        CellParticipantState, DocumentStore, LeaseDrainIntent, LeaseFreshness, LeaseReadiness,
        RegionDirectoryRecord, WorkflowInstance, WorkflowPhase,
    };

    use super::{
        CreateActivityRequest, CreateAlertRouteRequest, CreateAlertRuleRequest,
        CreateOtlpDispatchRequest, CreateOtlpExporterRequest, CreateSloRequest,
        CreateSlowPathRequest, EvaluateIncidentsRequest, ObserveIncident, ObserveService,
        ResolveIncidentRequest, data_state, ha_state, lifecycle_state, node_state,
    };
    use time::OffsetDateTime;
    use uhost_core::sha256_hex;
    use uhost_types::{AuditId, OwnershipScope, ResourceMetadata};

    fn parse_timestamp(value: &str) -> OffsetDateTime {
        OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|error| panic!("{error}"))
    }

    fn workflow_instance<T>(id: &str, phase: WorkflowPhase, state: T) -> WorkflowInstance<T> {
        let created_at = parse_timestamp("2026-04-08T12:00:00Z");
        WorkflowInstance {
            id: String::from(id),
            workflow_kind: String::from("test.workflow"),
            subject_kind: String::from("test_subject"),
            subject_id: String::from(id),
            phase,
            current_step_index: None,
            steps: Vec::new(),
            created_at,
            updated_at: created_at,
            completed_at: None,
            next_attempt_at: None,
            runner_claim: None,
            state,
        }
    }

    fn scoped_metadata(region: Option<&str>, cell_id: Option<&str>) -> ResourceMetadata {
        let seed = format!("{}:{}", region.unwrap_or("none"), cell_id.unwrap_or("none"));
        let mut metadata = ResourceMetadata::new(
            OwnershipScope::Platform,
            Some(seed.clone()),
            sha256_hex(seed.as_bytes()),
        );
        if let Some(region) = region {
            metadata
                .annotations
                .insert(String::from("region"), String::from(region));
        }
        if let Some(cell_id) = cell_id {
            metadata
                .annotations
                .insert(String::from("cell_id"), String::from(cell_id));
        }
        metadata
    }

    #[tokio::test]
    async fn node_health_summary_reads_sibling_node_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let heartbeats = DocumentStore::<node_state::NodeHeartbeatRecord>::open(
            temp.path().join("node/heartbeats.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        heartbeats
            .create(
                "nod_a",
                node_state::NodeHeartbeatRecord {
                    node_id: uhost_types::NodeId::parse(String::from("nod_aaaaaaaaaaaaaaaaaaaa"))
                        .unwrap_or_else(|error| panic!("{error}")),
                    hostname: String::from("node-a.example.com"),
                    healthy: false,
                    agent_version: String::from("1.0.0"),
                    cache_bytes: 128,
                    last_seen: time::OffsetDateTime::parse(
                        "2026-04-08T12:00:00Z",
                        &time::format_description::well_known::Rfc3339,
                    )
                    .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        heartbeats
            .create(
                "nod_b",
                node_state::NodeHeartbeatRecord {
                    node_id: uhost_types::NodeId::parse(String::from("nod_bbbbbbbbbbbbbbbbbbbb"))
                        .unwrap_or_else(|error| panic!("{error}")),
                    hostname: String::from("node-b.example.com"),
                    healthy: true,
                    agent_version: String::from("1.0.1"),
                    cache_bytes: 64,
                    last_seen: time::OffsetDateTime::parse(
                        "2026-04-08T11:55:00Z",
                        &time::format_description::well_known::Rfc3339,
                    )
                    .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reports = DocumentStore::<node_state::ProcessReportRecord>::open(
            temp.path().join("node/process_reports.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        reports
            .create(
                "wrk_1",
                node_state::ProcessReportRecord {
                    node_id: uhost_types::NodeId::parse(String::from("nod_aaaaaaaaaaaaaaaaaaaa"))
                        .unwrap_or_else(|error| panic!("{error}")),
                    workload_id: uhost_types::WorkloadId::parse(String::from(
                        "wrk_aaaaaaaaaaaaaaaaaaaa",
                    ))
                    .unwrap_or_else(|error| panic!("{error}")),
                    state: String::from("running"),
                    exit_code: None,
                    updated_at: time::OffsetDateTime::parse(
                        "2026-04-08T12:01:00Z",
                        &time::format_description::well_known::Rfc3339,
                    )
                    .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        reports
            .create(
                "wrk_2",
                node_state::ProcessReportRecord {
                    node_id: uhost_types::NodeId::parse(String::from("nod_bbbbbbbbbbbbbbbbbbbb"))
                        .unwrap_or_else(|error| panic!("{error}")),
                    workload_id: uhost_types::WorkloadId::parse(String::from(
                        "wrk_bbbbbbbbbbbbbbbbbbbb",
                    ))
                    .unwrap_or_else(|error| panic!("{error}")),
                    state: String::from("running"),
                    exit_code: None,
                    updated_at: time::OffsetDateTime::parse(
                        "2026-04-08T12:02:00Z",
                        &time::format_description::well_known::Rfc3339,
                    )
                    .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        reports
            .create(
                "wrk_3",
                node_state::ProcessReportRecord {
                    node_id: uhost_types::NodeId::parse(String::from("nod_aaaaaaaaaaaaaaaaaaaa"))
                        .unwrap_or_else(|error| panic!("{error}")),
                    workload_id: uhost_types::WorkloadId::parse(String::from(
                        "wrk_cccccccccccccccccccc",
                    ))
                    .unwrap_or_else(|error| panic!("{error}")),
                    state: String::from("crashed"),
                    exit_code: Some(137),
                    updated_at: time::OffsetDateTime::parse(
                        "2026-04-08T12:03:00Z",
                        &time::format_description::well_known::Rfc3339,
                    )
                    .unwrap_or_else(|error| panic!("{error}")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let service = ObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let summary = service.node_health_summary();

        assert_eq!(summary.total_nodes, 2);
        assert_eq!(summary.healthy_nodes, 1);
        assert_eq!(summary.unhealthy_nodes, 1);
        assert_eq!(summary.total_process_reports, 3);
        assert_eq!(summary.unique_workloads, 3);
        assert!(summary.heartbeats_available);
        assert!(summary.process_reports_available);
        assert_eq!(
            summary.recent_heartbeats[0].node_id.as_str(),
            "nod_aaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(summary.recent_heartbeats[0].reported_workloads, 2);
        assert_eq!(summary.process_report_totals[0].state, "running");
        assert_eq!(summary.process_report_totals[0].report_count, 2);
        assert_eq!(summary.process_report_totals[0].unique_nodes, 2);
    }

    #[tokio::test]
    async fn node_health_summary_handles_missing_sibling_node_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let summary = service.node_health_summary();

        assert_eq!(summary.total_nodes, 0);
        assert_eq!(summary.total_process_reports, 0);
        assert_eq!(summary.unique_workloads, 0);
        assert!(!summary.heartbeats_available);
        assert!(!summary.process_reports_available);
        assert!(summary.recent_heartbeats.is_empty());
        assert!(summary.process_report_totals.is_empty());
    }

    #[tokio::test]
    async fn error_budget_calculation_uses_activity_and_slow_paths() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_slo(CreateSloRequest {
                name: String::from("api-availability"),
                sli_kind: String::from("request"),
                target_success_per_million: 995_000,
                window_minutes: 60,
                alert_route_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_activity(CreateActivityRequest {
                category: String::from("request"),
                summary: String::from("request ok"),
                correlation_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_slow_path(CreateSlowPathRequest {
                category: String::from("request"),
                resource: String::from("/api/v1/items"),
                latency_ms: 1400,
                exemplar_trace_id: Some(String::from("trace-1")),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let budgets = service
            .error_budgets()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(budgets.len(), 1);
        assert!(budgets[0].measured_success_per_million < 1_000_000);
    }

    #[tokio::test]
    async fn otlp_dispatch_records_attempt() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_otlp_exporter(CreateOtlpExporterRequest {
                signal: String::from("traces"),
                endpoint: String::from("https://otlp.example.local/v1/traces"),
                insecure: false,
                headers: BTreeMap::new(),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let exporters = service
            .otlp_exporters
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let exporter_id = exporters[0].1.value.id.to_string();

        let _ = service
            .create_otlp_dispatch(CreateOtlpDispatchRequest {
                exporter_id,
                batch_items: 32,
                payload_bytes: 128_000,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let attempts = service
            .otlp_dispatch
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].1.value.status, "sent");
    }

    #[tokio::test]
    async fn incident_evaluation_routes_triggered_alert_rule() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_alert_route(CreateAlertRouteRequest {
                name: String::from("pager"),
                destination: String::from("pager://ops"),
                severity_filter: vec![String::from("high"), String::from("critical")],
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_alert_rule(CreateAlertRuleRequest {
                name: String::from("latency-slo"),
                expression: String::from("latency_ms>500"),
                severity: String::from("high"),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_slow_path(CreateSlowPathRequest {
                category: String::from("request"),
                resource: String::from("/api/v1/slow"),
                latency_ms: 900,
                exemplar_trace_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .evaluate_incidents(EvaluateIncidentsRequest {
                include_alert_rules: Some(true),
                include_slos: Some(false),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::OK);
        let incidents = service
            .incidents
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].1.value.source_kind, "alert_rule");
        assert_eq!(
            incidents[0].1.value.destination.as_deref(),
            Some("pager://ops")
        );
    }

    #[tokio::test]
    async fn slo_breach_creates_resolvable_incident() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_alert_route(CreateAlertRouteRequest {
                name: String::from("slo-route"),
                destination: String::from("email://sre@uhost.local"),
                severity_filter: vec![String::from("critical")],
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let route_id = service
            .alert_routes
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing alert route"));
        let _ = service
            .create_slo(CreateSloRequest {
                name: String::from("api-availability"),
                sli_kind: String::from("request"),
                target_success_per_million: 999_000,
                window_minutes: 30,
                alert_route_id: Some(route_id),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_activity(CreateActivityRequest {
                category: String::from("request"),
                summary: String::from("failed request"),
                correlation_id: Some(String::from("trace-breach")),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_slow_path(CreateSlowPathRequest {
                category: String::from("request"),
                resource: String::from("/api/v1/items"),
                latency_ms: 2500,
                exemplar_trace_id: Some(String::from("trace-breach")),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .evaluate_incidents(EvaluateIncidentsRequest {
                include_alert_rules: Some(false),
                include_slos: Some(true),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let incident = service
            .incidents
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.clone())
            .unwrap_or_else(|| panic!("missing incident"));
        assert_eq!(incident.source_kind, "slo");
        assert_eq!(incident.status, "open");

        let resolved = service
            .resolve_incident(
                incident.id.as_str(),
                ResolveIncidentRequest {
                    reason: Some(String::from("remediated regression")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(resolved.status(), http::StatusCode::OK);
        let stored = service
            .incidents
            .get(incident.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing resolved incident"));
        assert_eq!(stored.value.status, "resolved");
        assert!(stored.value.resolved_at.is_some());
    }

    #[tokio::test]
    async fn deleted_records_are_ignored_by_analysis_paths() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_slo(CreateSloRequest {
                name: String::from("api-availability"),
                sli_kind: String::from("request"),
                target_success_per_million: 995_000,
                window_minutes: 60,
                alert_route_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let slo = service
            .slos
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .next()
            .map(|(_, value)| value)
            .unwrap_or_else(|| panic!("missing slo"));
        service
            .slos
            .soft_delete(slo.value.id.as_str(), Some(1))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_activity(CreateActivityRequest {
                category: String::from("request"),
                summary: String::from("request ok"),
                correlation_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let activity = service
            .activity
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .next()
            .map(|(_, value)| value)
            .unwrap_or_else(|| panic!("missing activity"));
        service
            .activity
            .soft_delete(activity.value.id.as_str(), Some(1))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_slow_path(CreateSlowPathRequest {
                category: String::from("request"),
                resource: String::from("/api/v1/items"),
                latency_ms: 1400,
                exemplar_trace_id: Some(String::from("trace-1")),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let slow_path = service
            .slow_paths
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .next()
            .map(|(_, value)| value)
            .unwrap_or_else(|| panic!("missing slow path"));
        service
            .slow_paths
            .soft_delete(slow_path.value.id.as_str(), Some(1))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let budgets = service
            .error_budgets()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(budgets.is_empty());

        let exemplars = service
            .exemplars()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(exemplars.is_empty());

        let response = service
            .evaluate_incidents(EvaluateIncidentsRequest {
                include_alert_rules: Some(false),
                include_slos: Some(true),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::OK);
        let incidents = service
            .incidents
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(incidents.is_empty());
    }

    #[tokio::test]
    async fn incident_evaluation_does_not_duplicate_open_sources() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_alert_route(CreateAlertRouteRequest {
                name: String::from("pager"),
                destination: String::from("pager://ops"),
                severity_filter: vec![String::from("high")],
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_alert_rule(CreateAlertRuleRequest {
                name: String::from("latency-slo"),
                expression: String::from("latency_ms>500"),
                severity: String::from("high"),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_slow_path(CreateSlowPathRequest {
                category: String::from("request"),
                resource: String::from("/api/v1/slow"),
                latency_ms: 900,
                exemplar_trace_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first = service
            .evaluate_incidents(EvaluateIncidentsRequest {
                include_alert_rules: Some(true),
                include_slos: Some(false),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first.status(), http::StatusCode::OK);
        let second = service
            .evaluate_incidents(EvaluateIncidentsRequest {
                include_alert_rules: Some(true),
                include_slos: Some(false),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second.status(), http::StatusCode::OK);

        let incidents = service
            .incidents
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(incidents.len(), 1);
    }

    #[tokio::test]
    async fn observe_summary_reflects_persisted_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_alert_rule(CreateAlertRuleRequest {
                name: String::from("latency-rule"),
                expression: String::from("latency_ms>200"),
                severity: String::from("high"),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_activity(CreateActivityRequest {
                category: String::from("request"),
                summary: String::from("test activity"),
                correlation_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_otlp_exporter(CreateOtlpExporterRequest {
                signal: String::from("logs"),
                endpoint: String::from("https://otlp.example.local/v1/logs"),
                insecure: false,
                headers: BTreeMap::new(),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let exporter_id = service
            .otlp_exporters
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, stored)| stored.value.id.to_string())
            .unwrap_or_else(|| panic!("missing exporter"));
        let _ = service
            .create_otlp_dispatch(CreateOtlpDispatchRequest {
                exporter_id,
                batch_items: 8,
                payload_bytes: 65_536,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_alert_route(CreateAlertRouteRequest {
                name: String::from("pager"),
                destination: String::from("pager://ops"),
                severity_filter: vec![String::from("high")],
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_slo(CreateSloRequest {
                name: String::from("api-availability"),
                sli_kind: String::from("request"),
                target_success_per_million: 999_000,
                window_minutes: 15,
                alert_route_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_slow_path(CreateSlowPathRequest {
                category: String::from("request"),
                resource: String::from("/api/v1/test"),
                latency_ms: 1200,
                exemplar_trace_id: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let incident_id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let incident = ObserveIncident {
            id: incident_id.clone(),
            source_kind: String::from("alert_rule"),
            source_id: String::from("source-1"),
            severity: String::from("high"),
            summary: String::from("test incident"),
            route_id: None,
            destination: None,
            status: String::from("open"),
            correlation_id: None,
            created_at: OffsetDateTime::now_utc(),
            resolved_at: None,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(incident_id.to_string()),
                sha256_hex(incident_id.as_str().as_bytes()),
            ),
        };
        service
            .incidents
            .create(incident_id.as_str(), incident.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .observe_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.alert_rule_count, 1);
        assert_eq!(summary.activity_count, 1);
        assert_eq!(summary.activity_category_counts.get("request"), Some(&1));
        assert_eq!(summary.otlp_exporter_count, 1);
        assert_eq!(summary.otlp_exporter_enabled_count, 1);
        assert_eq!(summary.otlp_dispatch_count, 1);
        assert_eq!(summary.dispatch_status_counts.get("sent"), Some(&1));
        assert_eq!(summary.slo_count, 1);
        assert_eq!(summary.slo_window_minutes.get(&15), Some(&1));
        assert_eq!(summary.alert_route_count, 1);
        assert_eq!(summary.slow_path_count, 1);
        assert_eq!(summary.incident_count, 1);
        assert_eq!(summary.incident_status_counts.get("open"), Some(&1));
    }

    #[tokio::test]
    async fn fleet_ops_rollups_handle_missing_sibling_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let rollups = service
            .fleet_ops_rollups()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(rollups.state_root, temp.path().display().to_string());
        assert_eq!(rollups.ha_readiness.total_regions, 0);
        assert_eq!(rollups.ha_readiness.total_cells, 0);
        assert_eq!(rollups.incident_state.total_incidents, 0);
        assert_eq!(rollups.backlog_health.attention_items, 0);
        assert!(rollups.regions.is_empty());
        assert!(rollups.cells.is_empty());
    }

    #[tokio::test]
    async fn fleet_ops_rollups_fall_back_to_legacy_repair_job_projection_when_workflows_absent() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let repair_jobs = DocumentStore::<lifecycle_state::RepairJobRecord>::open(
            temp.path().join("lifecycle/repair_jobs.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        repair_jobs
            .create(
                "repair-active",
                lifecycle_state::RepairJobRecord {
                    status: String::from("pending_confirmation"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        repair_jobs
            .create(
                "repair-failed",
                lifecycle_state::RepairJobRecord {
                    status: String::from("failed"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        repair_jobs
            .create(
                "repair-completed",
                lifecycle_state::RepairJobRecord {
                    status: String::from("completed"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let service = ObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let rollups = service
            .fleet_ops_rollups()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(rollups.backlog_health.lifecycle_repair_jobs_active, 1);
        assert_eq!(rollups.backlog_health.lifecycle_repair_jobs_failed, 1);
        assert_eq!(rollups.backlog_health.attention_items, 1);
        assert_eq!(rollups.backlog_health.critical_items, 1);
    }

    #[tokio::test]
    async fn fleet_ops_rollups_merge_cells_regions_incidents_and_backlog() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let now = parse_timestamp("2026-04-08T12:00:00Z");

        let cells = DocumentStore::<CellDirectoryRecord>::open(
            temp.path().join("runtime/cell-directory.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let east = RegionDirectoryRecord::new("region-east", "Region East");
        let west = RegionDirectoryRecord::new("region-west", "Region West");
        let fresh_lease = CellParticipantLeaseState::new(
            now,
            now + time::Duration::minutes(5),
            300,
            LeaseFreshness::Fresh,
        );
        let stale_lease = CellParticipantLeaseState::new(
            now,
            now + time::Duration::seconds(30),
            300,
            LeaseFreshness::Stale,
        );

        let cell_a = CellDirectoryRecord::new("cell-a", "Cell A", east.clone()).with_participant(
            CellParticipantRecord::new("reg-a", "runtime_process", "subject-a", "control")
                .with_state(CellParticipantState::new(
                    LeaseReadiness::Ready,
                    LeaseDrainIntent::Serving,
                    fresh_lease.clone(),
                )),
        );
        let cell_b = CellDirectoryRecord::new("cell-b", "Cell B", east.clone()).with_participant(
            CellParticipantRecord::new("reg-b", "runtime_process", "subject-b", "control")
                .with_state(CellParticipantState::new(
                    LeaseReadiness::Ready,
                    LeaseDrainIntent::Draining,
                    stale_lease,
                )),
        );
        let cell_c = CellDirectoryRecord::new("cell-c", "Cell C", west.clone()).with_participant(
            CellParticipantRecord::new("reg-c", "runtime_process", "subject-c", "control")
                .with_state(CellParticipantState::new(
                    LeaseReadiness::Ready,
                    LeaseDrainIntent::Serving,
                    fresh_lease,
                )),
        );
        cells
            .create("cell-a", cell_a)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        cells
            .create("cell-b", cell_b)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        cells
            .create("cell-c", cell_c)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reconciliations = DocumentStore::<ha_state::ReconciliationRecord>::open(
            temp.path().join("ha/reconciliations.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        reconciliations
            .create(
                "region-east",
                ha_state::ReconciliationRecord {
                    region: String::from("region-east"),
                    latest_log_index: 12,
                    committed_log_index: 10,
                    majority_threshold: 2,
                    healthy_votes: 1,
                    uncommitted_entries: 2,
                    lagging_nodes: vec![String::from("nod-east-2")],
                    fully_reconciled: false,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        reconciliations
            .create(
                "region-west",
                ha_state::ReconciliationRecord {
                    region: String::from("region-west"),
                    latest_log_index: 8,
                    committed_log_index: 8,
                    majority_threshold: 2,
                    healthy_votes: 2,
                    uncommitted_entries: 0,
                    lagging_nodes: Vec::new(),
                    fully_reconciled: true,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let dependencies = DocumentStore::<ha_state::DependencyStatusRecord>::open(
            temp.path().join("ha/dependencies.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        dependencies
            .create(
                "dns",
                ha_state::DependencyStatusRecord {
                    dependency: String::from("dns"),
                    status: String::from("down"),
                    critical: true,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        dependencies
            .create(
                "storage",
                ha_state::DependencyStatusRecord {
                    dependency: String::from("storage"),
                    status: String::from("degraded"),
                    critical: true,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let ha_failovers =
            DocumentStore::<ha_state::FailoverRecord>::open(temp.path().join("ha/failovers.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        ha_failovers
            .create(
                "failover-running",
                ha_state::FailoverRecord {
                    state: String::from("in_progress"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        ha_failovers
            .create(
                "failover-failed",
                ha_state::FailoverRecord {
                    state: String::from("failed"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let ha_repair_workflows = DocumentStore::<ha_state::RepairWorkflow>::open(
            temp.path().join("ha/repair_workflows.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        ha_repair_workflows
            .create(
                "repair-running",
                workflow_instance(
                    "repair-running",
                    WorkflowPhase::Running,
                    ha_state::RepairWorkflowState,
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        ha_repair_workflows
            .create(
                "repair-failed",
                workflow_instance(
                    "repair-failed",
                    WorkflowPhase::Failed,
                    ha_state::RepairWorkflowState,
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let dead_letters = DocumentStore::<lifecycle_state::DeadLetterRecord>::open(
            temp.path().join("lifecycle/dead_letters.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        dead_letters
            .create(
                "dlq-pending",
                lifecycle_state::DeadLetterRecord { replayed: false },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        dead_letters
            .create(
                "dlq-replayed",
                lifecycle_state::DeadLetterRecord { replayed: true },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let repair_job_workflows = DocumentStore::<lifecycle_state::RepairJobWorkflow>::open(
            temp.path().join("lifecycle/repair_job_workflows.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        repair_job_workflows
            .create(
                "repair-active",
                workflow_instance(
                    "repair-active",
                    WorkflowPhase::Running,
                    lifecycle_state::RepairJobRecord {
                        status: String::from("pending_confirmation"),
                    },
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        repair_job_workflows
            .create(
                "repair-failed",
                workflow_instance(
                    "repair-failed",
                    WorkflowPhase::Failed,
                    lifecycle_state::RepairJobRecord {
                        status: String::from("failed"),
                    },
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let repair_jobs = DocumentStore::<lifecycle_state::RepairJobRecord>::open(
            temp.path().join("lifecycle/repair_jobs.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        repair_jobs
            .create(
                "repair-projection-completed",
                lifecycle_state::RepairJobRecord {
                    status: String::from("completed"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let data_failovers = DocumentStore::<data_state::DataFailoverRecord>::open(
            temp.path().join("data/failovers.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        data_failovers
            .create(
                "data-failover-running",
                data_state::DataFailoverRecord {
                    state: String::from("running"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        data_failovers
            .create(
                "data-failover-failed",
                data_state::DataFailoverRecord {
                    state: String::from("failed"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let data_failover_workflows = DocumentStore::<data_state::FailoverWorkflow>::open(
            temp.path().join("data/failover_workflows.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        data_failover_workflows
            .create(
                "data-failover-workflow",
                workflow_instance(
                    "data-failover-workflow",
                    WorkflowPhase::Running,
                    data_state::FailoverWorkflowState {
                        target_region: String::from("region-west"),
                    },
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let migrations = DocumentStore::<data_state::DataMigrationJob>::open(
            temp.path().join("data/migrations.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        migrations
            .create(
                "migration-running",
                data_state::DataMigrationJob {
                    state: String::from("running"),
                    source_region: Some(String::from("region-east")),
                    target_region: Some(String::from("region-west")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        migrations
            .create(
                "migration-failed",
                data_state::DataMigrationJob {
                    state: String::from("failed"),
                    source_region: Some(String::from("region-east")),
                    target_region: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let service = ObserveService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let incident_a_id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        service
            .incidents
            .create(
                incident_a_id.as_str(),
                ObserveIncident {
                    id: incident_a_id.clone(),
                    source_kind: String::from("alert_rule"),
                    source_id: String::from("region-east-cell-a"),
                    severity: String::from("critical"),
                    summary: String::from("cell a unavailable"),
                    route_id: None,
                    destination: None,
                    status: String::from("open"),
                    correlation_id: None,
                    created_at: now,
                    resolved_at: None,
                    metadata: scoped_metadata(Some("region-east"), Some("cell-a")),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let incident_b_id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        service
            .incidents
            .create(
                incident_b_id.as_str(),
                ObserveIncident {
                    id: incident_b_id.clone(),
                    source_kind: String::from("slo"),
                    source_id: String::from("region-west"),
                    severity: String::from("high"),
                    summary: String::from("region west latency"),
                    route_id: None,
                    destination: None,
                    status: String::from("open"),
                    correlation_id: None,
                    created_at: now,
                    resolved_at: None,
                    metadata: scoped_metadata(Some("region-west"), None),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let incident_c_id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        service
            .incidents
            .create(
                incident_c_id.as_str(),
                ObserveIncident {
                    id: incident_c_id.clone(),
                    source_kind: String::from("alert_rule"),
                    source_id: String::from("global"),
                    severity: String::from("medium"),
                    summary: String::from("global incident"),
                    route_id: None,
                    destination: None,
                    status: String::from("resolved"),
                    correlation_id: None,
                    created_at: now,
                    resolved_at: Some(now),
                    metadata: scoped_metadata(None, None),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let rollups = service
            .fleet_ops_rollups()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(rollups.ha_readiness.total_regions, 2);
        assert_eq!(rollups.ha_readiness.ready_regions, 1);
        assert_eq!(rollups.ha_readiness.degraded_regions, 1);
        assert_eq!(rollups.ha_readiness.regions_missing_reconciliation, 0);
        assert_eq!(rollups.ha_readiness.unreconciled_regions, 1);
        assert_eq!(rollups.ha_readiness.total_cells, 3);
        assert_eq!(rollups.ha_readiness.ready_cells, 2);
        assert_eq!(rollups.ha_readiness.degraded_cells, 1);
        assert_eq!(rollups.ha_readiness.critical_dependencies_down, 1);
        assert_eq!(rollups.ha_readiness.critical_dependencies_degraded, 1);

        assert_eq!(rollups.incident_state.total_incidents, 3);
        assert_eq!(rollups.incident_state.open_incidents, 2);
        assert_eq!(rollups.incident_state.resolved_incidents, 1);
        assert_eq!(rollups.incident_state.attributed_region_incidents, 2);
        assert_eq!(rollups.incident_state.attributed_cell_incidents, 1);
        assert_eq!(rollups.incident_state.unattributed_incidents, 1);
        assert_eq!(rollups.backlog_health.attention_items, 6);
        assert_eq!(rollups.backlog_health.critical_items, 5);
        assert_eq!(rollups.backlog_health.ha_failovers_in_progress, 1);
        assert_eq!(rollups.backlog_health.ha_failovers_failed, 1);
        assert_eq!(rollups.backlog_health.ha_repair_workflows_active, 1);
        assert_eq!(rollups.backlog_health.ha_repair_workflows_failed, 1);
        assert_eq!(rollups.backlog_health.lifecycle_dead_letters_pending, 1);
        assert_eq!(rollups.backlog_health.lifecycle_repair_jobs_active, 1);
        assert_eq!(rollups.backlog_health.lifecycle_repair_jobs_failed, 1);
        assert_eq!(rollups.backlog_health.data_failovers_active, 1);
        assert_eq!(rollups.backlog_health.data_failovers_failed, 1);
        assert_eq!(rollups.backlog_health.data_migrations_active, 1);
        assert_eq!(rollups.backlog_health.data_migrations_failed, 1);

        let east_region = rollups
            .regions
            .iter()
            .find(|region| region.region_id == "region-east")
            .unwrap_or_else(|| panic!("missing east region"));
        assert!(!east_region.ha_readiness.ready);
        assert_eq!(east_region.ha_readiness.total_cells, 2);
        assert_eq!(east_region.ha_readiness.degraded_cells, 1);
        assert_eq!(east_region.ha_readiness.uncommitted_entries, 2);
        assert_eq!(east_region.ha_readiness.lagging_nodes, 1);
        assert_eq!(east_region.incident_state.open_incidents, 1);
        assert_eq!(east_region.backlog_health.data_migrations_active, 1);
        assert_eq!(east_region.backlog_health.data_migrations_failed, 1);
        assert_eq!(east_region.backlog_health.uncommitted_entries, 2);

        let west_region = rollups
            .regions
            .iter()
            .find(|region| region.region_id == "region-west")
            .unwrap_or_else(|| panic!("missing west region"));
        assert!(west_region.ha_readiness.ready);
        assert_eq!(west_region.incident_state.open_incidents, 1);
        assert_eq!(west_region.backlog_health.data_migrations_active, 1);
        assert_eq!(west_region.backlog_health.data_failovers_active, 1);

        let cell_a = rollups
            .cells
            .iter()
            .find(|cell| cell.cell_id == "cell-a")
            .unwrap_or_else(|| panic!("missing cell-a"));
        assert!(cell_a.ha_readiness.ready);
        assert_eq!(cell_a.incident_state.open_incidents, 1);

        let cell_b = rollups
            .cells
            .iter()
            .find(|cell| cell.cell_id == "cell-b")
            .unwrap_or_else(|| panic!("missing cell-b"));
        assert!(!cell_b.ha_readiness.ready);
        assert_eq!(cell_b.ha_readiness.draining_participants, 1);
        assert_eq!(cell_b.ha_readiness.stale_participants, 1);
        assert_eq!(cell_b.backlog_health.takeover_pending, 1);
        assert_eq!(cell_b.backlog_health.attention_items, 2);
    }
}
