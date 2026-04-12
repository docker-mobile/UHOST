//! Control-plane workload and deployment service.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use http::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{PlatformError, RequestContext, Result, sha256_hex};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{
    AuditLog, CellDirectoryCollection, CellServiceGroupConflictState, DocumentStore, DurableOutbox,
    resolve_cell_service_group_directory,
};
use uhost_types::{
    AuditActor, AuditId, DeploymentId, EventHeader, EventPayload, NodeId, OwnershipScope,
    PlatformEvent, PriorityClass, ProjectId, ResourceLifecycleState, ResourceMetadata,
    ServiceEvent, ShardPlacementId, WorkloadId,
};

/// Workload declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadRecord {
    pub id: WorkloadId,
    pub project_id: ProjectId,
    pub name: String,
    pub kind: String,
    pub image: Option<String>,
    pub command: Vec<String>,
    pub replicas: u32,
    pub priority: PriorityClass,
    pub metadata: ResourceMetadata,
}

/// Deployment declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentRecord {
    pub id: DeploymentId,
    pub workload_id: WorkloadId,
    pub release_channel: String,
    pub strategy: String,
    pub desired_revision: String,
    pub rollout_state: String,
    pub metadata: ResourceMetadata,
}

/// Scope bound by one shard-placement object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardPlacementBindingScope {
    Deployment,
    Replica,
}

impl ShardPlacementBindingScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Deployment => "deployment",
            Self::Replica => "replica",
        }
    }
}

/// Spread requirements carried by one shard-placement object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardPlacementSpreadPolicy {
    pub min_distinct_cells: u32,
    pub min_distinct_nodes: u32,
}

impl ShardPlacementSpreadPolicy {
    fn validate(&self) -> Result<()> {
        if self.min_distinct_cells == 0 {
            return Err(PlatformError::invalid(
                "spread.min_distinct_cells must be at least 1",
            ));
        }
        if self.min_distinct_nodes == 0 {
            return Err(PlatformError::invalid(
                "spread.min_distinct_nodes must be at least 1",
            ));
        }
        Ok(())
    }
}

/// Failover modes carried by one shard-placement object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ShardPlacementFailoverMode {
    #[default]
    Disabled,
    ColdStandby,
    WarmStandby,
    ActivePassive,
}

impl ShardPlacementFailoverMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ColdStandby => "cold_standby",
            Self::WarmStandby => "warm_standby",
            Self::ActivePassive => "active_passive",
        }
    }
}

/// Failover coordination data carried by one shard-placement object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ShardPlacementFailoverRule {
    #[serde(default)]
    pub mode: ShardPlacementFailoverMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failover_group: Option<String>,
    #[serde(default)]
    pub priority: u32,
}

impl ShardPlacementFailoverRule {
    fn validate(&self) -> Result<()> {
        let has_group = self
            .failover_group
            .as_ref()
            .is_some_and(|value| !value.trim().is_empty());
        if self.mode == ShardPlacementFailoverMode::Disabled {
            if self.priority != 0 {
                return Err(PlatformError::invalid(
                    "failover.priority must be zero when failover is disabled",
                ));
            }
            if matches!(self.failover_group.as_deref(), Some(value) if value.trim().is_empty()) {
                return Err(PlatformError::invalid(
                    "failover.failover_group must not be blank",
                ));
            }
            return Ok(());
        }

        if !has_group {
            return Err(PlatformError::invalid(
                "failover.failover_group is required when failover mode is enabled",
            ));
        }
        if self.priority == 0 {
            return Err(PlatformError::invalid(
                "failover.priority must be at least 1 when failover mode is enabled",
            ));
        }
        Ok(())
    }
}

/// Durable shard-placement object binding one deployment or replica to one cell and optional node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardPlacementRecord {
    pub id: ShardPlacementId,
    pub deployment_id: DeploymentId,
    pub binding_scope: ShardPlacementBindingScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replica_ordinal: Option<u32>,
    pub cell_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<NodeId>,
    pub spread: ShardPlacementSpreadPolicy,
    #[serde(default)]
    pub failover: ShardPlacementFailoverRule,
    pub metadata: ResourceMetadata,
}

impl ShardPlacementRecord {
    fn matches_binding(
        &self,
        deployment_id: &DeploymentId,
        binding_scope: ShardPlacementBindingScope,
        replica_ordinal: Option<u32>,
        cell_id: &str,
        node_id: Option<&NodeId>,
    ) -> bool {
        self.deployment_id == *deployment_id
            && self.binding_scope == binding_scope
            && self.replica_ordinal == replica_ordinal
            && self.cell_id == cell_id
            && self.node_id.as_ref() == node_id
    }
}

/// Read-only operator summary for control-plane workloads and deployments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlSummary {
    pub workload_count: usize,
    pub deployment_count: usize,
    pub project_summaries: Vec<ProjectControlSummary>,
    pub workload_kind_totals: Vec<TotalByValue>,
    pub deployment_rollout_state_totals: Vec<TotalByValue>,
    pub unanchored_deployments: usize,
    pub registry: ControlRegistrySummary,
}

/// Per-project workload and deployment rollup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectControlSummary {
    pub project_id: ProjectId,
    pub workload_count: usize,
    pub deployment_count: usize,
    pub total_desired_replicas: u64,
    pub workload_kind_totals: Vec<TotalByValue>,
    pub deployment_rollout_state_totals: Vec<TotalByValue>,
}

/// Generic tally used in read-only summaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotalByValue {
    pub value: String,
    pub count: usize,
}

/// Registry-backed availability view for the logical `control` service-group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlRegistrySummary {
    pub healthy_cells: usize,
    pub conflicted_cells: usize,
    pub resolved_registrations: usize,
    pub cells: Vec<ControlRegistryCellSummary>,
}

/// One cell-scoped `control` service-group resolution slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlRegistryCellSummary {
    pub cell_id: String,
    pub cell_name: String,
    pub region_id: String,
    pub region_name: String,
    pub resolved_registration_ids: Vec<String>,
    pub conflict_state: CellServiceGroupConflictState,
    pub total_registrations: usize,
    pub healthy_registrations: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateWorkloadRequest {
    project_id: String,
    name: String,
    kind: String,
    image: Option<String>,
    command: Vec<String>,
    replicas: u32,
    priority: Option<PriorityClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateDeploymentRequest {
    workload_id: String,
    release_channel: String,
    strategy: String,
    desired_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateShardPlacementRequest {
    deployment_id: String,
    binding_scope: ShardPlacementBindingScope,
    replica_ordinal: Option<u32>,
    cell_id: String,
    node_id: Option<String>,
    spread: ShardPlacementSpreadPolicy,
    #[serde(default)]
    failover: ShardPlacementFailoverRule,
}

/// Control service.
#[derive(Debug, Clone)]
pub struct ControlService {
    workloads: DocumentStore<WorkloadRecord>,
    deployments: DocumentStore<DeploymentRecord>,
    shard_placements: DocumentStore<ShardPlacementRecord>,
    cell_directories: CellDirectoryCollection,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    state_root: PathBuf,
}

impl ControlService {
    /// Open the control service state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let state_root = state_root.as_ref();
        let root = state_root.join("control");
        Ok(Self {
            workloads: DocumentStore::open(root.join("workloads.json")).await?,
            deployments: DocumentStore::open(root.join("deployments.json")).await?,
            shard_placements: DocumentStore::open(root.join("shard-placements.json")).await?,
            cell_directories: CellDirectoryCollection::open_local(runtime_cell_directory_path(
                state_root,
            ))
            .await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            state_root: root,
        })
    }

    async fn create_workload(
        &self,
        request: CreateWorkloadRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let project_id = ProjectId::parse(request.project_id).map_err(|error| {
            PlatformError::invalid("invalid project_id").with_detail(error.to_string())
        })?;
        let id = WorkloadId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate workload id")
                .with_detail(error.to_string())
        })?;
        let workload = WorkloadRecord {
            id: id.clone(),
            project_id,
            name: request.name,
            kind: request.kind,
            image: request.image,
            command: request.command,
            replicas: request.replicas.max(1),
            priority: request.priority.unwrap_or(PriorityClass::Standard),
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.workloads.create(id.as_str(), workload.clone()).await?;
        self.append_event(
            "control.workload.created.v1",
            "workload",
            id.as_str(),
            serde_json::json!({ "kind": workload.kind, "replicas": workload.replicas }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &workload)
    }

    async fn create_deployment(
        &self,
        request: CreateDeploymentRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let workload_id = WorkloadId::parse(request.workload_id).map_err(|error| {
            PlatformError::invalid("invalid workload_id").with_detail(error.to_string())
        })?;
        let workload = self
            .workloads
            .get(workload_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("workload does not exist"))?;
        if workload.deleted {
            return Err(PlatformError::not_found("workload does not exist"));
        }
        let id = DeploymentId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate deployment id")
                .with_detail(error.to_string())
        })?;
        let deployment = DeploymentRecord {
            id: id.clone(),
            workload_id,
            release_channel: request.release_channel,
            strategy: request.strategy,
            desired_revision: request.desired_revision,
            rollout_state: String::from("pending"),
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.deployments
            .create(id.as_str(), deployment.clone())
            .await?;
        self.append_event(
            "control.deployment.created.v1",
            "deployment",
            id.as_str(),
            serde_json::json!({
                "strategy": deployment.strategy,
                "desired_revision": deployment.desired_revision,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &deployment)
    }

    async fn create_shard_placement(
        &self,
        request: CreateShardPlacementRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        request.spread.validate()?;
        request.failover.validate()?;

        let deployment_id = DeploymentId::parse(request.deployment_id).map_err(|error| {
            PlatformError::invalid("invalid deployment_id").with_detail(error.to_string())
        })?;
        let deployment = self
            .deployments
            .get(deployment_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("deployment does not exist"))?;
        if deployment.deleted {
            return Err(PlatformError::not_found("deployment does not exist"));
        }

        let workload = self
            .workloads
            .get(deployment.value.workload_id.as_str())
            .await?
            .ok_or_else(|| {
                PlatformError::conflict("deployment is not anchored to an active workload")
            })?;
        if workload.deleted {
            return Err(PlatformError::conflict(
                "deployment is not anchored to an active workload",
            ));
        }

        let cell_id = required_trimmed_string(&request.cell_id, "cell_id")?;
        let node_id = match request.node_id {
            Some(node_id) => Some(NodeId::parse(node_id).map_err(|error| {
                PlatformError::invalid("invalid node_id").with_detail(error.to_string())
            })?),
            None => None,
        };

        let replica_ordinal = match request.binding_scope {
            ShardPlacementBindingScope::Deployment => {
                if request.replica_ordinal.is_some() {
                    return Err(PlatformError::invalid(
                        "replica_ordinal is only valid for replica-scoped placements",
                    ));
                }
                if node_id.is_some() {
                    return Err(PlatformError::invalid(
                        "node_id is only valid for replica-scoped placements",
                    ));
                }
                None
            }
            ShardPlacementBindingScope::Replica => {
                let replica_ordinal = request.replica_ordinal.ok_or_else(|| {
                    PlatformError::invalid(
                        "replica_ordinal is required for replica-scoped placements",
                    )
                })?;
                if replica_ordinal >= workload.value.replicas {
                    return Err(PlatformError::invalid(format!(
                        "replica_ordinal must be less than workload replicas ({})",
                        workload.value.replicas
                    )));
                }
                Some(replica_ordinal)
            }
        };

        if self
            .list_active_shard_placements()
            .await?
            .into_iter()
            .any(|placement| {
                placement.matches_binding(
                    &deployment_id,
                    request.binding_scope,
                    replica_ordinal,
                    cell_id.as_str(),
                    node_id.as_ref(),
                )
            })
        {
            return Err(PlatformError::conflict(
                "shard placement already exists for the requested binding",
            ));
        }

        let id = ShardPlacementId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate shard placement id")
                .with_detail(error.to_string())
        })?;
        let mut metadata = ResourceMetadata::new(
            OwnershipScope::Project,
            Some(id.to_string()),
            sha256_hex(id.as_str().as_bytes()),
        );
        metadata.lifecycle = ResourceLifecycleState::Ready;

        let placement = ShardPlacementRecord {
            id: id.clone(),
            deployment_id: deployment_id.clone(),
            binding_scope: request.binding_scope,
            replica_ordinal,
            cell_id,
            node_id,
            spread: request.spread,
            failover: request.failover,
            metadata,
        };
        self.shard_placements
            .create(id.as_str(), placement.clone())
            .await?;
        self.append_event(
            "control.shard_placement.created.v1",
            "shard_placement",
            id.as_str(),
            serde_json::json!({
                "deployment_id": deployment_id.to_string(),
                "binding_scope": placement.binding_scope.as_str(),
                "replica_ordinal": placement.replica_ordinal,
                "cell_id": placement.cell_id.clone(),
                "node_id": placement.node_id.as_ref().map(ToString::to_string),
                "min_distinct_cells": placement.spread.min_distinct_cells,
                "min_distinct_nodes": placement.spread.min_distinct_nodes,
                "failover_mode": placement.failover.mode.as_str(),
                "failover_group": placement.failover.failover_group.clone(),
                "failover_priority": placement.failover.priority,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &placement)
    }

    async fn list_active_workloads(&self) -> Result<Vec<WorkloadRecord>> {
        Ok(self
            .workloads
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect())
    }

    async fn list_active_deployments(&self) -> Result<Vec<DeploymentRecord>> {
        Ok(self
            .deployments
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect())
    }

    async fn list_active_shard_placements(&self) -> Result<Vec<ShardPlacementRecord>> {
        Ok(self
            .shard_placements
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect())
    }

    async fn registry_summary(&self) -> Result<ControlRegistrySummary> {
        let mut cells = self
            .cell_directories
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .filter_map(|(_, record)| {
                let directory = resolve_cell_service_group_directory(&record.value);
                let control_entry = directory
                    .groups
                    .into_iter()
                    .find(|entry| entry.group == "control")?;
                Some(ControlRegistryCellSummary {
                    cell_id: directory.cell_id,
                    cell_name: directory.cell_name,
                    region_id: directory.region.region_id,
                    region_name: directory.region.region_name,
                    resolved_registration_ids: control_entry.resolved_registration_ids,
                    conflict_state: control_entry.conflict_state,
                    total_registrations: control_entry.registrations.len(),
                    healthy_registrations: control_entry
                        .registrations
                        .iter()
                        .filter(|registration| registration.healthy)
                        .count(),
                })
            })
            .collect::<Vec<_>>();
        cells.sort_by(|left, right| left.cell_id.cmp(&right.cell_id));

        Ok(ControlRegistrySummary {
            healthy_cells: cells
                .iter()
                .filter(|cell| !cell.resolved_registration_ids.is_empty())
                .count(),
            conflicted_cells: cells
                .iter()
                .filter(|cell| cell.conflict_state != CellServiceGroupConflictState::NoConflict)
                .count(),
            resolved_registrations: cells
                .iter()
                .map(|cell| cell.resolved_registration_ids.len())
                .sum(),
            cells,
        })
    }

    async fn summarize(&self) -> Result<ControlSummary> {
        let workloads = self.list_active_workloads().await?;
        let deployments = self.list_active_deployments().await?;
        let registry = self.registry_summary().await?;

        let mut workloads_by_project: BTreeMap<ProjectId, Vec<&WorkloadRecord>> = BTreeMap::new();
        let mut workload_by_id: BTreeMap<WorkloadId, &WorkloadRecord> = BTreeMap::new();
        let mut workload_kind_totals: BTreeMap<String, usize> = BTreeMap::new();

        for workload in &workloads {
            workloads_by_project
                .entry(workload.project_id.clone())
                .or_default()
                .push(workload);
            workload_by_id.insert(workload.id.clone(), workload);
            *workload_kind_totals
                .entry(workload.kind.clone())
                .or_default() += 1;
        }

        let mut deployment_rollout_state_totals: BTreeMap<String, usize> = BTreeMap::new();
        let mut deployments_by_project: BTreeMap<ProjectId, Vec<&DeploymentRecord>> =
            BTreeMap::new();
        let mut unanchored_deployments = 0_usize;
        for deployment in &deployments {
            *deployment_rollout_state_totals
                .entry(deployment.rollout_state.clone())
                .or_default() += 1;
            if let Some(workload) = workload_by_id.get(&deployment.workload_id) {
                deployments_by_project
                    .entry(workload.project_id.clone())
                    .or_default()
                    .push(deployment);
            } else {
                unanchored_deployments = unanchored_deployments.saturating_add(1);
            }
        }

        let project_ids = workloads_by_project.keys().cloned().collect::<Vec<_>>();
        let mut project_summaries = Vec::with_capacity(project_ids.len());
        for project_id in project_ids {
            let project_workloads = workloads_by_project.remove(&project_id).unwrap_or_default();
            let project_deployments = deployments_by_project
                .remove(&project_id)
                .unwrap_or_default();

            let total_desired_replicas = project_workloads.iter().fold(0_u64, |total, workload| {
                total.saturating_add(u64::from(workload.replicas))
            });

            let mut project_workload_kinds: BTreeMap<String, usize> = BTreeMap::new();
            for workload in &project_workloads {
                *project_workload_kinds
                    .entry(workload.kind.clone())
                    .or_default() += 1;
            }

            let mut project_rollout_states: BTreeMap<String, usize> = BTreeMap::new();
            for deployment in &project_deployments {
                *project_rollout_states
                    .entry(deployment.rollout_state.clone())
                    .or_default() += 1;
            }

            project_summaries.push(ProjectControlSummary {
                project_id,
                workload_count: project_workloads.len(),
                deployment_count: project_deployments.len(),
                total_desired_replicas,
                workload_kind_totals: map_to_totals(project_workload_kinds),
                deployment_rollout_state_totals: map_to_totals(project_rollout_states),
            });
        }

        Ok(ControlSummary {
            workload_count: workloads.len(),
            deployment_count: deployments.len(),
            project_summaries,
            workload_kind_totals: map_to_totals(workload_kind_totals),
            deployment_rollout_state_totals: map_to_totals(deployment_rollout_state_totals),
            unanchored_deployments,
            registry,
        })
    }

    async fn append_event(
        &self,
        event_type: &str,
        resource_kind: &str,
        resource_id: &str,
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
                source_service: String::from("control"),
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
                action: String::from("created"),
                details,
            }),
        };
        self.audit_log.append(&event).await?;
        let idempotency = event.header.event_id.to_string();
        let _ = self
            .outbox
            .enqueue("control.events.v1", event, Some(&idempotency))
            .await?;
        Ok(())
    }
}

impl HttpService for ControlService {
    fn name(&self) -> &'static str {
        "control"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/control")];
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
                (Method::GET, ["control"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                    }),
                )
                .map(Some),
                (Method::GET, ["control", "workloads"]) => {
                    json_response(StatusCode::OK, &self.list_active_workloads().await?).map(Some)
                }
                (Method::GET, ["control", "summary"]) => {
                    json_response(StatusCode::OK, &self.summarize().await?).map(Some)
                }
                (Method::POST, ["control", "workloads"]) => {
                    let body: CreateWorkloadRequest = parse_json(request).await?;
                    self.create_workload(body, &context).await.map(Some)
                }
                (Method::GET, ["control", "deployments"]) => {
                    json_response(StatusCode::OK, &self.list_active_deployments().await?).map(Some)
                }
                (Method::POST, ["control", "deployments"]) => {
                    let body: CreateDeploymentRequest = parse_json(request).await?;
                    self.create_deployment(body, &context).await.map(Some)
                }
                (Method::GET, ["control", "shard-placements"]) => {
                    json_response(StatusCode::OK, &self.list_active_shard_placements().await?)
                        .map(Some)
                }
                (Method::POST, ["control", "shard-placements"]) => {
                    let body: CreateShardPlacementRequest = parse_json(request).await?;
                    self.create_shard_placement(body, &context).await.map(Some)
                }
                (Method::GET, ["control", "outbox"]) => {
                    let messages = self.outbox.list_all().await?;
                    json_response(StatusCode::OK, &messages).map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn map_to_totals(input: BTreeMap<String, usize>) -> Vec<TotalByValue> {
    input
        .into_iter()
        .map(|(value, count)| TotalByValue { value, count })
        .collect()
}

fn runtime_cell_directory_path(state_root: &Path) -> PathBuf {
    state_root.join("runtime").join("cell-directory.json")
}

fn required_trimmed_string(value: &str, field: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(format!("{field} must not be blank")));
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use tempfile::tempdir;
    use time::OffsetDateTime;
    use uhost_core::{ErrorCode, RequestContext};
    use uhost_store::{
        CellDirectoryCollection, CellParticipantLeaseSource, CellParticipantLeaseState,
        CellParticipantRecord, CellParticipantState, LeaseDrainIntent, LeaseReadiness,
        LeaseRegistrationCollection, LeaseRegistrationRecord, LocalCellRegistry,
        LocalCellRegistryPublication, RegionDirectoryRecord,
    };
    use uhost_types::{NodeId, PriorityClass, ProjectId};

    use super::{
        ControlService, CreateDeploymentRequest, CreateShardPlacementRequest,
        CreateWorkloadRequest, ShardPlacementBindingScope, ShardPlacementFailoverMode,
        ShardPlacementFailoverRule, ShardPlacementSpreadPolicy, TotalByValue,
    };

    async fn create_deployment_for_test(
        service: &ControlService,
        context: &RequestContext,
        replicas: u32,
    ) -> (super::WorkloadRecord, super::DeploymentRecord) {
        service
            .create_workload(
                CreateWorkloadRequest {
                    project_id: ProjectId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    name: String::from("placement-workload"),
                    kind: String::from("container"),
                    image: Some(String::from("registry.local/placement:1")),
                    command: vec![String::from("/app/start")],
                    replicas,
                    priority: None,
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workload = service
            .list_active_workloads()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing workload"));

        service
            .create_deployment(
                CreateDeploymentRequest {
                    workload_id: workload.id.to_string(),
                    release_channel: String::from("stable"),
                    strategy: String::from("rolling"),
                    desired_revision: String::from("rev-placement"),
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let deployment = service
            .list_active_deployments()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing deployment"));
        (workload, deployment)
    }

    fn spread_policy() -> ShardPlacementSpreadPolicy {
        ShardPlacementSpreadPolicy {
            min_distinct_cells: 1,
            min_distinct_nodes: 1,
        }
    }

    #[tokio::test]
    async fn create_workload_writes_outbox_event() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_workload(
                CreateWorkloadRequest {
                    project_id: ProjectId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    name: String::from("web"),
                    kind: String::from("container"),
                    image: Some(String::from("registry.local/web:1")),
                    command: vec![String::from("/app/start")],
                    replicas: 2,
                    priority: Some(PriorityClass::Standard),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::CREATED);

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(outbox.len(), 1);
    }

    #[tokio::test]
    async fn list_workloads_skips_soft_deleted_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_workload(
                CreateWorkloadRequest {
                    project_id: ProjectId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    name: String::from("web"),
                    kind: String::from("container"),
                    image: Some(String::from("registry.local/web:1")),
                    command: vec![String::from("/app/start")],
                    replicas: 1,
                    priority: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), http::StatusCode::CREATED);

        let stored = service
            .workloads
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let (key, document) = stored
            .into_iter()
            .find(|(_, document)| !document.deleted)
            .unwrap_or_else(|| panic!("missing workload record"));
        service
            .workloads
            .soft_delete(key.as_str(), Some(document.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let workloads = service
            .list_active_workloads()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(workloads.is_empty());
    }

    #[test]
    fn create_workload_rejects_unknown_priority_values() {
        let request = serde_json::json!({
            "project_id": ProjectId::generate()
                .unwrap_or_else(|error| panic!("{error}"))
                .to_string(),
            "name": "web",
            "kind": "container",
            "image": "registry.local/web:1",
            "command": ["/app/start"],
            "replicas": 2,
            "priority": "urgent",
        });

        let error = serde_json::from_value::<CreateWorkloadRequest>(request)
            .expect_err("invalid priority should not deserialize");
        assert!(
            error.to_string().contains("unknown variant"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn create_deployment_rejects_soft_deleted_workload() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_workload(
                CreateWorkloadRequest {
                    project_id: ProjectId::generate()
                        .unwrap_or_else(|error| panic!("{error}"))
                        .to_string(),
                    name: String::from("worker"),
                    kind: String::from("container"),
                    image: Some(String::from("registry.local/worker:1")),
                    command: vec![String::from("/app/start")],
                    replicas: 1,
                    priority: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let (workload_key, stored) = service
            .workloads
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, stored)| !stored.deleted)
            .unwrap_or_else(|| panic!("missing workload"));
        service
            .workloads
            .soft_delete(workload_key.as_str(), Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_deployment(
                CreateDeploymentRequest {
                    workload_id: workload_key,
                    release_channel: String::from("stable"),
                    strategy: String::from("rolling"),
                    desired_revision: String::from("rev-2"),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected soft-deleted workload rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn create_shard_placement_writes_outbox_event() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let (_, deployment) = create_deployment_for_test(&service, &context, 2).await;

        let response = service
            .create_shard_placement(
                CreateShardPlacementRequest {
                    deployment_id: deployment.id.to_string(),
                    binding_scope: ShardPlacementBindingScope::Deployment,
                    replica_ordinal: None,
                    cell_id: String::from("iad-a"),
                    node_id: None,
                    spread: spread_policy(),
                    failover: ShardPlacementFailoverRule::default(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::CREATED);

        let placements = service
            .list_active_shard_placements()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(placements.len(), 1);
        assert_eq!(placements[0].deployment_id, deployment.id);
        assert_eq!(
            placements[0].binding_scope,
            ShardPlacementBindingScope::Deployment
        );

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(outbox.len(), 3);
    }

    #[tokio::test]
    async fn create_replica_shard_placement_rejects_out_of_range_replica_ordinal() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let (_, deployment) = create_deployment_for_test(&service, &context, 1).await;

        let error = service
            .create_shard_placement(
                CreateShardPlacementRequest {
                    deployment_id: deployment.id.to_string(),
                    binding_scope: ShardPlacementBindingScope::Replica,
                    replica_ordinal: Some(1),
                    cell_id: String::from("iad-a"),
                    node_id: Some(
                        NodeId::generate()
                            .unwrap_or_else(|error| panic!("{error}"))
                            .to_string(),
                    ),
                    spread: spread_policy(),
                    failover: ShardPlacementFailoverRule::default(),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected invalid replica ordinal"));
        assert_eq!(error.code, ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn create_shard_placement_rejects_duplicate_binding() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let (_, deployment) = create_deployment_for_test(&service, &context, 2).await;
        let node_id = NodeId::generate().unwrap_or_else(|error| panic!("{error}"));
        let request = CreateShardPlacementRequest {
            deployment_id: deployment.id.to_string(),
            binding_scope: ShardPlacementBindingScope::Replica,
            replica_ordinal: Some(0),
            cell_id: String::from("iad-a"),
            node_id: Some(node_id.to_string()),
            spread: spread_policy(),
            failover: ShardPlacementFailoverRule {
                mode: ShardPlacementFailoverMode::ActivePassive,
                failover_group: Some(String::from("api-rollout")),
                priority: 1,
            },
        };

        service
            .create_shard_placement(request.clone(), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let error = service
            .create_shard_placement(request, &context)
            .await
            .err()
            .unwrap_or_else(|| panic!("expected duplicate shard placement rejection"));
        assert_eq!(error.code, ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn list_shard_placements_skips_soft_deleted_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let (_, deployment) = create_deployment_for_test(&service, &context, 2).await;

        service
            .create_shard_placement(
                CreateShardPlacementRequest {
                    deployment_id: deployment.id.to_string(),
                    binding_scope: ShardPlacementBindingScope::Deployment,
                    replica_ordinal: None,
                    cell_id: String::from("iad-a"),
                    node_id: None,
                    spread: spread_policy(),
                    failover: ShardPlacementFailoverRule::default(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let (key, stored) = service
            .shard_placements
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, stored)| !stored.deleted)
            .unwrap_or_else(|| panic!("missing shard placement"));
        service
            .shard_placements
            .soft_delete(key.as_str(), Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let placements = service
            .list_active_shard_placements()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(placements.is_empty());
    }

    #[tokio::test]
    async fn summary_groups_workloads_and_deployments_by_project_anchor() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let project_a = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let project_b = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));

        let first = service
            .create_workload(
                CreateWorkloadRequest {
                    project_id: project_a.to_string(),
                    name: String::from("frontend"),
                    kind: String::from("container"),
                    image: Some(String::from("registry.local/frontend:1")),
                    command: vec![String::from("/app/start")],
                    replicas: 2,
                    priority: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first.status(), http::StatusCode::CREATED);
        let second = service
            .create_workload(
                CreateWorkloadRequest {
                    project_id: project_a.to_string(),
                    name: String::from("jobs"),
                    kind: String::from("batch"),
                    image: Some(String::from("registry.local/jobs:1")),
                    command: vec![String::from("/app/start")],
                    replicas: 1,
                    priority: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second.status(), http::StatusCode::CREATED);
        let third = service
            .create_workload(
                CreateWorkloadRequest {
                    project_id: project_b.to_string(),
                    name: String::from("api"),
                    kind: String::from("container"),
                    image: Some(String::from("registry.local/api:1")),
                    command: vec![String::from("/app/start")],
                    replicas: 3,
                    priority: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(third.status(), http::StatusCode::CREATED);

        let workloads = service
            .list_active_workloads()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        for workload in workloads {
            let created = service
                .create_deployment(
                    CreateDeploymentRequest {
                        workload_id: workload.id.to_string(),
                        release_channel: String::from("stable"),
                        strategy: String::from("rolling"),
                        desired_revision: String::from("rev-1"),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(created.status(), http::StatusCode::CREATED);
        }

        let summary = service
            .summarize()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.workload_count, 3);
        assert_eq!(summary.deployment_count, 3);
        assert_eq!(summary.unanchored_deployments, 0);
        assert_eq!(summary.workload_kind_totals.len(), 2);
        assert_eq!(summary.deployment_rollout_state_totals.len(), 1);
        assert!(summary.registry.cells.is_empty());
        assert_eq!(summary.registry.healthy_cells, 0);

        let project_ids = summary
            .project_summaries
            .iter()
            .map(|item| item.project_id.to_string())
            .collect::<BTreeSet<_>>();
        assert!(project_ids.contains(&project_a.to_string()));
        assert!(project_ids.contains(&project_b.to_string()));

        let project_a_summary = summary
            .project_summaries
            .iter()
            .find(|item| item.project_id == project_a)
            .unwrap_or_else(|| panic!("missing project-a summary"));
        assert_eq!(project_a_summary.workload_count, 2);
        assert_eq!(project_a_summary.deployment_count, 2);
        assert_eq!(project_a_summary.total_desired_replicas, 3);
    }

    #[tokio::test]
    async fn summary_tracks_unanchored_deployments_when_workload_is_deleted() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));

        service
            .create_workload(
                CreateWorkloadRequest {
                    project_id: project_id.to_string(),
                    name: String::from("api"),
                    kind: String::from("container"),
                    image: Some(String::from("registry.local/api:1")),
                    command: vec![String::from("/app/start")],
                    replicas: 1,
                    priority: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let workload = service
            .list_active_workloads()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing workload"));
        service
            .create_deployment(
                CreateDeploymentRequest {
                    workload_id: workload.id.to_string(),
                    release_channel: String::from("stable"),
                    strategy: String::from("rolling"),
                    desired_revision: String::from("rev-2"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored = service
            .workloads
            .get(workload.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing workload document"));
        service
            .workloads
            .soft_delete(workload.id.as_str(), Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .summarize()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.workload_count, 0);
        assert_eq!(summary.deployment_count, 1);
        assert_eq!(summary.unanchored_deployments, 1);
        assert!(summary.project_summaries.is_empty());
        assert!(summary.registry.cells.is_empty());
    }

    #[tokio::test]
    async fn summary_includes_control_group_resolution_from_local_cell_registry() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = ControlService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_root = temp.path().join("runtime");
        let registry =
            LocalCellRegistry::open_local(runtime_root.join("local-registry-state.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store =
            CellDirectoryCollection::open_local(super::runtime_cell_directory_path(temp.path()))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let registration_store = LeaseRegistrationCollection::open_local(
            runtime_root.join("process-registrations.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let registration = registration_store
            .upsert(
                "control:node-a",
                LeaseRegistrationRecord::new(
                    "control:node-a",
                    "runtime_process",
                    "control:node-a",
                    "control",
                    Some(String::from("node-a")),
                    15,
                )
                .with_readiness(LeaseReadiness::Ready)
                .with_drain_intent(LeaseDrainIntent::Serving),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .value;
        let observed_at = OffsetDateTime::now_utc();
        let participant = CellParticipantRecord::new(
            "control:node-a",
            "runtime_process",
            "control:node-a",
            "control",
        )
        .with_node_name("node-a")
        .with_service_groups(["control"])
        .with_lease_registration_id("control:node-a")
        .with_state(
            CellParticipantState::new(
                LeaseReadiness::Ready,
                LeaseDrainIntent::Serving,
                CellParticipantLeaseState::new(
                    registration.lease_renewed_at,
                    registration.lease_expires_at,
                    registration.lease_duration_seconds,
                    registration.lease_freshness_at(observed_at),
                ),
            )
            .with_lease_source(CellParticipantLeaseSource::LinkedRegistration),
        );
        registry
            .publish(
                &cell_directory_store,
                &registration_store,
                &LocalCellRegistryPublication::new(
                    "local:cell-a",
                    "cell-a",
                    RegionDirectoryRecord::new("local", "local"),
                    registration,
                    participant,
                )
                .with_directory_reconciliation_ownership(true),
                observed_at,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .summarize()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.registry.healthy_cells, 1);
        assert_eq!(summary.registry.conflicted_cells, 0);
        assert_eq!(summary.registry.resolved_registrations, 1);
        assert_eq!(summary.registry.cells.len(), 1);

        let cell = summary
            .registry
            .cells
            .first()
            .unwrap_or_else(|| panic!("missing control registry cell summary"));
        assert_eq!(cell.cell_id, "local:cell-a");
        assert_eq!(cell.cell_name, "cell-a");
        assert_eq!(cell.region_id, "local");
        assert_eq!(cell.region_name, "local");
        assert_eq!(
            cell.resolved_registration_ids,
            vec![String::from("control:node-a")]
        );
        assert_eq!(cell.total_registrations, 1);
        assert_eq!(cell.healthy_registrations, 1);
    }

    #[test]
    fn map_to_totals_orders_keys_lexicographically() {
        let mut input = BTreeMap::new();
        input.insert(String::from("running"), 2);
        input.insert(String::from("pending"), 1);
        let totals = super::map_to_totals(input);
        let expected = vec![
            TotalByValue {
                value: String::from("pending"),
                count: 1,
            },
            TotalByValue {
                value: String::from("running"),
                count: 2,
            },
        ];
        assert_eq!(totals, expected);
    }
}
