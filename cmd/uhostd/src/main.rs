use std::collections::BTreeMap;
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod activation;

#[cfg(test)]
use activation::runtime_topology;
use activation::{
    RUNTIME_INTERNAL_ROUTE_AUDIENCES, RUNTIME_INTERNAL_ROUTE_SURFACES, RuntimeRolePublicationPlan,
    RuntimeServiceFactoryContext, parse_runtime_process_role,
    runtime_participant_tombstone_history_entry_from_record, runtime_role_publication_plan,
    supported_runtime_process_role_names,
};
use http::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use time::{Duration as TimeDuration, OffsetDateTime};

use uhost_api::{ApiBody, json_response, parse_json, parse_query, path_segments};
use uhost_core::{
    ConfigLoader, ConfigSchema, ErrorCode, LoadableConfig, PlatformError, RequestContext, Result,
    SecretBytes, SecretString, base64url_decode, base64url_encode,
};
use uhost_runtime::{
    HttpIdempotencyJournal, HttpService, PlatformRuntime, RuntimeAccessConfig,
    RuntimeCellMembership, RuntimeParticipantTombstoneHistoryEntry, RuntimeProcessRole,
    RuntimeReadyzFailureReason, RuntimeReadyzHandle, RuntimeRegionMembership,
    RuntimeTopologyHandle, StaticServiceForwarder,
};
use uhost_store::{
    AuditLog, CellDirectoryCollection, CellDirectoryRecord, CellParticipantReconciliationState,
    CellParticipantRecord, CellServiceGroupDirectoryCollection, DeliveryState, DurableEventRelay,
    EventRelayEnvelope, LeaseDrainIntent, LeaseFreshness, LeaseReadiness,
    LeaseRegistrationCollection, LeaseRegistrationRecord, LocalCellRegistry,
    LocalCellRegistryPublication, ParticipantTombstoneHistoryCollection,
    ParticipantTombstoneHistoryRecord, RegionDirectoryRecord, RelayPublishRequest,
    ServiceEndpointCollection, ServiceInstanceCollection, StaleParticipantCleanupStage,
    StaleParticipantCleanupWorkflowState, StoredDocument, WorkflowCollection, WorkflowInstance,
    WorkflowPhase, WorkflowStepState, resolve_cell_service_group_directory,
    stale_participant_cleanup_workflow, stale_participant_cleanup_workflow_id,
};
use uhost_svc_identity::IdentityService;
use uhost_types::{
    AuditActor, AuditId, EventHeader, EventPayload, PageCursor, PlatformEvent, ServiceEvent,
    ServiceMode,
};

const MIN_BOOTSTRAP_ADMIN_TOKEN_LEN: usize = 32;
const RUNTIME_PROCESS_SUBJECT_KIND: &str = "runtime_process";
const RUNTIME_PROCESS_LEASE_DURATION_SECONDS: u32 = 15;
const RUNTIME_PROCESS_LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(5);
const MAX_TOPOLOGY_LABEL_LEN: usize = 64;
const DEFAULT_LOCAL_REGION_NAME: &str = "local";
const DEFAULT_LOCAL_CELL_NAME: &str = "local-cell";
const RUNTIME_TOMBSTONE_HISTORY_PAGE_DEFAULT_LIMIT: usize = 25;
const RUNTIME_TOMBSTONE_HISTORY_PAGE_MAX_LIMIT: usize = 100;
const RUNTIME_TOMBSTONE_HISTORY_RETENTION_LIMIT: usize = 128;
const RUNTIME_SOURCE_SERVICE: &str = "runtime";
const RUNTIME_EVENTS_TOPIC: &str = "runtime.events.v1";
const RUNTIME_PARTICIPANT_TOMBSTONED_EVENT_TYPE: &str = "runtime.participant.tombstoned.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeCellPlacement {
    region_id: String,
    region_name: String,
    cell_id: String,
    cell_name: String,
}

impl RuntimeCellPlacement {
    fn new(region_name: String, cell_name: String) -> Self {
        let region_id = region_name.clone();
        let cell_id = format!("{region_id}:{cell_name}");
        Self {
            region_id,
            region_name,
            cell_id,
            cell_name,
        }
    }

    fn region_membership(&self) -> RuntimeRegionMembership {
        RuntimeRegionMembership::new(self.region_id.clone(), self.region_name.clone())
    }

    fn cell_membership(&self) -> RuntimeCellMembership {
        RuntimeCellMembership::new(self.cell_id.clone(), self.cell_name.clone())
    }

    #[cfg(test)]
    fn region_record(&self) -> RegionDirectoryRecord {
        RegionDirectoryRecord::new(self.region_id.clone(), self.region_name.clone())
    }
}

fn runtime_registration_store_path(state_dir: &Path) -> PathBuf {
    state_dir.join("runtime").join("process-registrations.json")
}

fn runtime_cell_directory_store_path(state_dir: &Path) -> PathBuf {
    state_dir.join("runtime").join("cell-directory.json")
}

fn runtime_service_group_directory_store_path(state_dir: &Path) -> PathBuf {
    state_dir
        .join("runtime")
        .join("service-group-directory.json")
}

#[cfg(test)]
fn runtime_service_instance_store_path(state_dir: &Path) -> PathBuf {
    state_dir.join("runtime").join("service-instances.json")
}

#[cfg(test)]
fn runtime_service_endpoint_store_path(state_dir: &Path) -> PathBuf {
    state_dir.join("runtime").join("service-endpoints.json")
}

fn runtime_stale_participant_cleanup_store_path(state_dir: &Path) -> PathBuf {
    state_dir
        .join("runtime")
        .join("stale-participant-cleanup-workflows.json")
}

fn runtime_participant_tombstone_history_store_path(state_dir: &Path) -> PathBuf {
    state_dir
        .join("runtime")
        .join("participant-tombstone-history.json")
}

fn runtime_audit_log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("runtime").join("audit.log")
}

fn runtime_outbox_path(state_dir: &Path) -> PathBuf {
    state_dir.join("runtime").join("outbox.json")
}

fn runtime_idempotency_journal_path(state_dir: &Path) -> PathBuf {
    state_dir
        .join("runtime")
        .join("http-idempotency-journal.json")
}

fn runtime_registry_reconciler_store_path(state_dir: &Path) -> PathBuf {
    state_dir.join("runtime").join("registry-reconciler.json")
}

#[derive(Debug, Clone)]
struct RuntimeRegistryReconciler {
    registry: LocalCellRegistry,
    service_instance_store: ServiceInstanceCollection,
    service_endpoint_store: ServiceEndpointCollection,
    publication_plan: RuntimeRolePublicationPlan,
    listener_address: SocketAddr,
}

impl RuntimeRegistryReconciler {
    fn new(
        registry: LocalCellRegistry,
        service_instance_store: ServiceInstanceCollection,
        service_endpoint_store: ServiceEndpointCollection,
        publication_plan: RuntimeRolePublicationPlan,
        listener_address: SocketAddr,
    ) -> Self {
        Self {
            registry,
            service_instance_store,
            service_endpoint_store,
            publication_plan,
            listener_address,
        }
    }

    async fn open_local(
        path: impl AsRef<Path>,
        publication_plan: RuntimeRolePublicationPlan,
        listener_address: SocketAddr,
    ) -> Result<Self> {
        let path = path.as_ref();
        let runtime_dir = path.parent().ok_or_else(|| {
            PlatformError::invalid("runtime registry reconciler store path must have a parent")
        })?;
        Ok(Self::new(
            LocalCellRegistry::open_local(path).await?,
            ServiceInstanceCollection::open(runtime_dir.join("service-instances.json")).await?,
            ServiceEndpointCollection::open(runtime_dir.join("service-endpoints.json")).await?,
            publication_plan,
            listener_address,
        ))
    }

    async fn reconcile_cell_directory(
        &self,
        cell_directory_store: &CellDirectoryCollection,
        registration_store: &LeaseRegistrationCollection,
        cleanup_workflow_store: &WorkflowCollection<StaleParticipantCleanupWorkflowState>,
        registration: &LeaseRegistrationRecord,
        observed_at: OffsetDateTime,
    ) -> Result<CellDirectoryRecord> {
        // Publication is two-phase on purpose: first publish this process into
        // the local registry and service tables, then, only for the role that
        // owns reconciliation, fold cleanup-workflow state back into the stored
        // cell directory with a versioned update.
        let publication_plan = self.publication_plan.clone();
        let publication = LocalCellRegistryPublication::new(
            publication_plan.cell().cell_id.clone(),
            publication_plan.cell().cell_name.clone(),
            RegionDirectoryRecord::new(
                publication_plan.region().region_id.clone(),
                publication_plan.region().region_name.clone(),
            ),
            registration.clone(),
            publication_plan.cell_participant(registration, observed_at),
        )
        .with_directory_reconciliation_ownership(
            publication_plan.owns_runtime_registry_reconciliation(),
        )
        .with_service_endpoint_bindings(
            publication_plan.service_endpoint_bindings(self.listener_address),
        );
        let mut cell_directory = self
            .registry
            .publish_with_service_records(
                cell_directory_store,
                registration_store,
                &self.service_instance_store,
                &self.service_endpoint_store,
                &publication,
                observed_at,
            )
            .await?;
        if publication_plan.owns_runtime_registry_reconciliation() {
            let stored_cell_directory = cell_directory_store
                .get(publication_plan.cell().cell_id.as_str())
                .await?
                .filter(|stored| !stored.deleted)
                .ok_or_else(|| {
                    PlatformError::not_found(format!(
                        "cell directory `{}` does not exist",
                        publication_plan.cell().cell_id.as_str()
                    ))
                })?;
            let mut updated_cell_directory = stored_cell_directory.value.clone();
            reconcile_runtime_stale_participant_cleanup_workflows(
                cleanup_workflow_store,
                &mut updated_cell_directory,
                registration.registration_id.as_str(),
                observed_at,
            )
            .await?;
            if updated_cell_directory != stored_cell_directory.value {
                cell_directory = cell_directory_store
                    .upsert(
                        publication_plan.cell().cell_id.as_str(),
                        updated_cell_directory,
                        Some(stored_cell_directory.version),
                    )
                    .await?
                    .value;
            } else {
                cell_directory = stored_cell_directory.value;
            }
        }
        Ok(cell_directory)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct TombstoneRuntimeParticipantRequest {
    registration_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TombstoneRuntimeParticipantReply {
    cell_id: String,
    participant_registration_id: String,
    cleanup_workflow_id: String,
    tombstoned_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    lease_registration_id: Option<String>,
    removed_from_cell_directory: bool,
    lease_registration_soft_deleted: bool,
    cleanup_workflow_soft_deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeParticipantTombstoneHistoryCursor {
    tombstoned_at_nanos: i128,
    event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeParticipantTombstoneHistoryQuery {
    limit: usize,
    cursor: Option<RuntimeParticipantTombstoneHistoryCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RuntimeParticipantTombstoneHistoryRetention {
    max_entries: usize,
    retained_entries: usize,
    pruned_entries: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    oldest_retained_tombstoned_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oldest_retained_event_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RuntimeParticipantTombstoneHistoryProjection {
    items: Vec<RuntimeParticipantTombstoneHistoryEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<PageCursor>,
    retention: RuntimeParticipantTombstoneHistoryRetention,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeParticipantTombstoneHistorySnapshot {
    records: Vec<ParticipantTombstoneHistoryRecord>,
    retention: RuntimeParticipantTombstoneHistoryRetention,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeParticipantTombstoneAggregateQuery {
    limit: usize,
    cursor: Option<RuntimeParticipantTombstoneHistoryCursor>,
    event_id: Option<String>,
    cell_id: Option<String>,
    region_id: Option<String>,
    participant_registration_id: Option<String>,
    cleanup_workflow_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RuntimeParticipantTombstoneRelayEvidence {
    message_id: String,
    topic: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    idempotency_key: Option<String>,
    source_service: String,
    event_type: String,
    delivery_state: String,
    backend: String,
    attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_attempt_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivered_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_retry_at: Option<OffsetDateTime>,
    replay_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_replayed_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_replay_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RuntimeParticipantTombstoneAggregateEntry {
    history: RuntimeParticipantTombstoneHistoryEntry,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_evidence: Option<RuntimeParticipantTombstoneRelayEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RuntimeParticipantTombstoneAggregateProjection {
    items: Vec<RuntimeParticipantTombstoneAggregateEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<PageCursor>,
    retention: RuntimeParticipantTombstoneHistoryRetention,
}

fn parse_runtime_participant_tombstone_history_query(
    raw: &BTreeMap<String, String>,
) -> Result<RuntimeParticipantTombstoneHistoryQuery> {
    let limit = raw.get("limit").map_or_else(
        || Ok(RUNTIME_TOMBSTONE_HISTORY_PAGE_DEFAULT_LIMIT),
        |value| {
            let parsed = value.parse::<usize>().map_err(|error| {
                PlatformError::invalid("invalid runtime tombstone history limit").with_detail(
                    format!("`{value}` is not a valid positive integer: {error}"),
                )
            })?;
            if parsed == 0 {
                return Err(
                    PlatformError::invalid("invalid runtime tombstone history limit")
                        .with_detail("limit must be greater than zero"),
                );
            }
            Ok(parsed.min(RUNTIME_TOMBSTONE_HISTORY_PAGE_MAX_LIMIT))
        },
    )?;
    let cursor = raw
        .get("cursor")
        .map(|value| parse_runtime_participant_tombstone_history_cursor(value))
        .transpose()?;
    Ok(RuntimeParticipantTombstoneHistoryQuery { limit, cursor })
}

fn parse_runtime_participant_tombstone_aggregate_query(
    raw: &BTreeMap<String, String>,
) -> Result<RuntimeParticipantTombstoneAggregateQuery> {
    let base = parse_runtime_participant_tombstone_history_query(raw)?;
    Ok(RuntimeParticipantTombstoneAggregateQuery {
        limit: base.limit,
        cursor: base.cursor,
        event_id: parse_runtime_participant_tombstone_exact_filter(raw, "event_id")?,
        cell_id: parse_runtime_participant_tombstone_exact_filter(raw, "cell_id")?,
        region_id: parse_runtime_participant_tombstone_exact_filter(raw, "region_id")?,
        participant_registration_id: parse_runtime_participant_tombstone_exact_filter(
            raw,
            "participant_registration_id",
        )?,
        cleanup_workflow_id: parse_runtime_participant_tombstone_exact_filter(
            raw,
            "cleanup_workflow_id",
        )?,
    })
}

fn parse_runtime_participant_tombstone_exact_filter(
    raw: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<String>> {
    raw.get(key)
        .map(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(PlatformError::invalid(format!(
                    "invalid runtime tombstone aggregate {key} filter"
                ))
                .with_detail(format!("`{key}` may not be empty")));
            }
            Ok(trimmed.to_owned())
        })
        .transpose()
}

fn parse_runtime_participant_tombstone_history_cursor(
    raw: &str,
) -> Result<RuntimeParticipantTombstoneHistoryCursor> {
    let decoded = base64url_decode(raw).map_err(|error| {
        PlatformError::invalid("invalid runtime tombstone history cursor")
            .with_detail(error.to_string())
    })?;
    let decoded = String::from_utf8(decoded).map_err(|error| {
        PlatformError::invalid("invalid runtime tombstone history cursor")
            .with_detail(format!("cursor payload must be valid UTF-8: {error}"))
    })?;
    let (tombstoned_at_nanos, event_id) = decoded.split_once(':').ok_or_else(|| {
        PlatformError::invalid("invalid runtime tombstone history cursor")
            .with_detail("cursor payload must use `<unix_timestamp_nanos>:<event_id>`")
    })?;
    let tombstoned_at_nanos = tombstoned_at_nanos.parse::<i128>().map_err(|error| {
        PlatformError::invalid("invalid runtime tombstone history cursor")
            .with_detail(format!("cursor timestamp is invalid: {error}"))
    })?;
    let event_id = event_id.trim();
    if event_id.is_empty() {
        return Err(
            PlatformError::invalid("invalid runtime tombstone history cursor")
                .with_detail("cursor event_id may not be empty"),
        );
    }
    Ok(RuntimeParticipantTombstoneHistoryCursor {
        tombstoned_at_nanos,
        event_id: event_id.to_owned(),
    })
}

fn encode_runtime_participant_tombstone_history_cursor(
    record: &ParticipantTombstoneHistoryRecord,
) -> PageCursor {
    PageCursor::new(base64url_encode(
        format!(
            "{}:{}",
            record.tombstoned_at.unix_timestamp_nanos(),
            record.event_id
        )
        .as_bytes(),
    ))
}

fn runtime_participant_tombstone_history_record_is_after_cursor(
    record: &ParticipantTombstoneHistoryRecord,
    cursor: &RuntimeParticipantTombstoneHistoryCursor,
) -> bool {
    let record_tombstoned_at = record.tombstoned_at.unix_timestamp_nanos();
    record_tombstoned_at < cursor.tombstoned_at_nanos
        || (record_tombstoned_at == cursor.tombstoned_at_nanos && record.event_id > cursor.event_id)
}

fn compare_runtime_participant_tombstone_history_records(
    left: &ParticipantTombstoneHistoryRecord,
    right: &ParticipantTombstoneHistoryRecord,
) -> std::cmp::Ordering {
    right
        .tombstoned_at
        .cmp(&left.tombstoned_at)
        .then_with(|| left.event_id.cmp(&right.event_id))
}

fn runtime_participant_tombstone_history_projection(
    history: &[ParticipantTombstoneHistoryRecord],
    query: &RuntimeParticipantTombstoneHistoryQuery,
    retention: RuntimeParticipantTombstoneHistoryRetention,
) -> RuntimeParticipantTombstoneHistoryProjection {
    let mut page = history
        .iter()
        .filter(|record| match query.cursor.as_ref() {
            Some(cursor) => {
                runtime_participant_tombstone_history_record_is_after_cursor(record, cursor)
            }
            None => true,
        })
        .take(query.limit.saturating_add(1))
        .collect::<Vec<_>>();
    let has_more = page.len() > query.limit;
    if has_more {
        page.truncate(query.limit);
    }
    let next_cursor = if has_more {
        page.last()
            .map(|record| encode_runtime_participant_tombstone_history_cursor(record))
    } else {
        None
    };
    RuntimeParticipantTombstoneHistoryProjection {
        items: page
            .into_iter()
            .map(runtime_participant_tombstone_history_entry_from_record)
            .collect(),
        next_cursor,
        retention,
    }
}

fn runtime_participant_tombstone_exact_filter_matches(
    actual: &str,
    expected: Option<&str>,
) -> bool {
    match expected {
        Some(expected) => actual == expected,
        None => true,
    }
}

fn runtime_participant_tombstone_history_record_matches_aggregate_query(
    record: &ParticipantTombstoneHistoryRecord,
    query: &RuntimeParticipantTombstoneAggregateQuery,
) -> bool {
    runtime_participant_tombstone_exact_filter_matches(
        record.event_id.as_str(),
        query.event_id.as_deref(),
    ) && runtime_participant_tombstone_exact_filter_matches(
        record.cell_id.as_str(),
        query.cell_id.as_deref(),
    ) && runtime_participant_tombstone_exact_filter_matches(
        record.region_id.as_str(),
        query.region_id.as_deref(),
    ) && runtime_participant_tombstone_exact_filter_matches(
        record.participant_registration_id.as_str(),
        query.participant_registration_id.as_deref(),
    ) && runtime_participant_tombstone_exact_filter_matches(
        record.cleanup_workflow_id.as_str(),
        query.cleanup_workflow_id.as_deref(),
    )
}

fn runtime_participant_tombstone_relay_delivery_state(state: &DeliveryState) -> &'static str {
    match state {
        DeliveryState::Pending => "pending",
        DeliveryState::Failed { .. } => "failed",
        DeliveryState::Delivered { .. } => "delivered",
    }
}

fn runtime_participant_tombstone_relay_event_matches(
    envelope: &EventRelayEnvelope<PlatformEvent>,
) -> bool {
    let source_service = envelope
        .source_service
        .as_deref()
        .unwrap_or(envelope.payload.header.source_service.as_str());
    let event_type = envelope
        .event_type
        .as_deref()
        .unwrap_or(envelope.payload.header.event_type.as_str());
    if source_service != RUNTIME_SOURCE_SERVICE
        || event_type != RUNTIME_PARTICIPANT_TOMBSTONED_EVENT_TYPE
    {
        return false;
    }
    if let EventPayload::Service(service) = &envelope.payload.payload {
        service.resource_kind == "cell_participant" && service.action == "tombstoned"
    } else {
        false
    }
}

fn runtime_participant_tombstone_relay_event_id(
    envelope: &EventRelayEnvelope<PlatformEvent>,
) -> Option<String> {
    if !runtime_participant_tombstone_relay_event_matches(envelope) {
        return None;
    }
    let idempotency_key = envelope
        .idempotency_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_owned());
    Some(idempotency_key.unwrap_or_else(|| envelope.payload.header.event_id.to_string()))
}

fn runtime_participant_tombstone_relay_evidence_from_envelope(
    envelope: &EventRelayEnvelope<PlatformEvent>,
) -> RuntimeParticipantTombstoneRelayEvidence {
    RuntimeParticipantTombstoneRelayEvidence {
        message_id: envelope.id.clone(),
        topic: envelope.topic.clone(),
        idempotency_key: envelope
            .idempotency_key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_owned()),
        source_service: envelope
            .source_service
            .clone()
            .unwrap_or_else(|| envelope.payload.header.source_service.clone()),
        event_type: envelope
            .event_type
            .clone()
            .unwrap_or_else(|| envelope.payload.header.event_type.clone()),
        delivery_state: String::from(runtime_participant_tombstone_relay_delivery_state(
            &envelope.state,
        )),
        backend: envelope.relay.backend.clone(),
        attempts: envelope.relay.attempts,
        last_attempt_at: envelope.relay.last_attempt_at,
        delivered_at: envelope.relay.delivered_at,
        last_error: envelope.relay.last_error.clone(),
        next_retry_at: envelope.relay.next_retry_at,
        replay_count: envelope.relay.replay_count,
        last_replayed_at: envelope.relay.last_replayed_at,
        last_replay_reason: envelope.relay.last_replay_reason.clone(),
    }
}

fn runtime_participant_tombstone_relay_evidence_is_newer(
    current: &EventRelayEnvelope<PlatformEvent>,
    candidate: &EventRelayEnvelope<PlatformEvent>,
) -> bool {
    candidate.updated_at > current.updated_at
        || (candidate.updated_at == current.updated_at && candidate.id > current.id)
}

fn runtime_participant_tombstone_aggregate_projection(
    history: &[ParticipantTombstoneHistoryRecord],
    relay_evidence: &BTreeMap<String, EventRelayEnvelope<PlatformEvent>>,
    query: &RuntimeParticipantTombstoneAggregateQuery,
    retention: RuntimeParticipantTombstoneHistoryRetention,
) -> RuntimeParticipantTombstoneAggregateProjection {
    let mut page = history
        .iter()
        .filter(|record| {
            runtime_participant_tombstone_history_record_matches_aggregate_query(record, query)
        })
        .filter(|record| match query.cursor.as_ref() {
            Some(cursor) => {
                runtime_participant_tombstone_history_record_is_after_cursor(record, cursor)
            }
            None => true,
        })
        .take(query.limit.saturating_add(1))
        .collect::<Vec<_>>();
    let has_more = page.len() > query.limit;
    if has_more {
        page.truncate(query.limit);
    }
    let next_cursor = if has_more {
        page.last()
            .map(|record| encode_runtime_participant_tombstone_history_cursor(record))
    } else {
        None
    };
    RuntimeParticipantTombstoneAggregateProjection {
        items: page
            .into_iter()
            .map(|record| RuntimeParticipantTombstoneAggregateEntry {
                history: runtime_participant_tombstone_history_entry_from_record(record),
                relay_evidence: relay_evidence
                    .get(record.event_id.as_str())
                    .map(runtime_participant_tombstone_relay_evidence_from_envelope),
            })
            .collect(),
        next_cursor,
        retention,
    }
}

fn runtime_participant_cleanup_workflow_is_tombstone_eligible(
    workflow: &WorkflowInstance<StaleParticipantCleanupWorkflowState>,
    cell_id: &str,
    participant: &CellParticipantRecord,
) -> bool {
    workflow.workflow_kind == "runtime.participant.cleanup.v1"
        && workflow.subject_kind == "cell_participant"
        && workflow.subject_id == participant.registration_id
        && workflow.phase == WorkflowPhase::Running
        && workflow.current_step_index == Some(2)
        && workflow.state.cell_id == cell_id
        && workflow.state.participant_registration_id == participant.registration_id
        && workflow.state.participant_subject_id == participant.subject_id
        && workflow.state.participant_role == participant.role
        && workflow.state.stage == StaleParticipantCleanupStage::TombstoneEligible
        && workflow.state.tombstone_eligible_at.is_some()
}

fn durable_stale_participant_cleanup_workflow<'a>(
    workflow_documents: &'a BTreeMap<
        String,
        StoredDocument<WorkflowInstance<StaleParticipantCleanupWorkflowState>>,
    >,
    cell_id: &str,
    participant: &CellParticipantRecord,
) -> Option<&'a WorkflowInstance<StaleParticipantCleanupWorkflowState>> {
    let workflow_id =
        stale_participant_cleanup_workflow_id(cell_id, participant.registration_id.as_str());
    let workflow = workflow_documents
        .get(&workflow_id)
        .filter(|stored| !stored.deleted)
        .map(|stored| &stored.value)?;
    if workflow.workflow_kind != "runtime.participant.cleanup.v1"
        || workflow.subject_kind != "cell_participant"
        || workflow.subject_id != participant.registration_id
        || workflow.state.cell_id != cell_id
        || workflow.state.participant_registration_id != participant.registration_id
        || workflow.state.participant_subject_id != participant.subject_id
        || workflow.state.participant_role != participant.role
    {
        return None;
    }
    if let Some(state) = participant.state.as_ref()
        && state.lease.renewed_at > workflow.state.last_observed_stale_at
    {
        return None;
    }
    Some(workflow)
}

fn durable_participant_reconciliation_state(
    participant: &CellParticipantRecord,
    workflow: Option<&WorkflowInstance<StaleParticipantCleanupWorkflowState>>,
) -> Option<CellParticipantReconciliationState> {
    match (participant.reconciliation.as_ref(), workflow) {
        (Some(previous), Some(workflow)) => {
            let mut merged = previous.clone();
            if merged.stale_since.is_none() {
                merged = merged.with_stale_since(workflow.state.stale_since);
            }
            if workflow.state.last_observed_stale_at > merged.last_reconciled_at {
                merged.last_reconciled_at = workflow.state.last_observed_stale_at;
            }
            if merged.cleanup_workflow_id.is_none() {
                merged = merged.with_cleanup_workflow_id(workflow.id.clone());
            }
            Some(merged)
        }
        (Some(previous), None) => Some(previous.clone()),
        (None, Some(workflow)) => Some(
            CellParticipantReconciliationState::new(workflow.state.last_observed_stale_at)
                .with_stale_since(workflow.state.stale_since)
                .with_cleanup_workflow_id(workflow.id.clone()),
        ),
        (None, None) => None,
    }
}

const STALE_PARTICIPANT_PREFLIGHT_CONFIRMATION_OBSERVATIONS: u32 = 2;
const STALE_PARTICIPANT_TOMBSTONE_ELIGIBILITY_OBSERVATIONS: u32 = 3;
const STALE_PARTICIPANT_REVIEW_STEP_INDEX: usize = 0;
const STALE_PARTICIPANT_PREFLIGHT_STEP_INDEX: usize = 1;
const STALE_PARTICIPANT_TOMBSTONE_STEP_INDEX: usize = 2;

fn stale_participant_cleanup_threshold(duration_seconds: u32) -> TimeDuration {
    TimeDuration::seconds(i64::from(duration_seconds.max(1)))
}

fn stale_participant_cleanup_retry_interval() -> TimeDuration {
    match i64::try_from(RUNTIME_PROCESS_LEASE_RENEW_INTERVAL.as_secs()) {
        Ok(seconds) => TimeDuration::seconds(seconds.max(1)),
        Err(_) => TimeDuration::seconds(i64::MAX),
    }
}

fn stale_participant_cleanup_runner_lease_duration() -> TimeDuration {
    stale_participant_cleanup_threshold(RUNTIME_PROCESS_LEASE_DURATION_SECONDS)
}

fn stale_participant_cleanup_next_attempt_at(observed_at: OffsetDateTime) -> OffsetDateTime {
    observed_at + stale_participant_cleanup_retry_interval()
}

fn stale_participant_cleanup_workflow_has_follow_up(
    workflow: &WorkflowInstance<StaleParticipantCleanupWorkflowState>,
) -> bool {
    !matches!(
        workflow.phase,
        WorkflowPhase::Completed | WorkflowPhase::Failed | WorkflowPhase::RolledBack
    ) && workflow.state.stage != StaleParticipantCleanupStage::TombstoneEligible
}

fn stale_participant_cleanup_workflow_claimed_by_other_runner(
    workflow: &WorkflowInstance<StaleParticipantCleanupWorkflowState>,
    self_registration_id: &str,
    observed_at: OffsetDateTime,
) -> bool {
    workflow.runner_claim.as_ref().is_some_and(|claim| {
        claim.runner_id != self_registration_id && claim.is_active_at(observed_at)
    })
}

fn schedule_stale_participant_cleanup_next_attempt(
    workflow: &mut WorkflowInstance<StaleParticipantCleanupWorkflowState>,
    observed_at: OffsetDateTime,
) {
    let next_attempt_at = if stale_participant_cleanup_workflow_has_follow_up(workflow) {
        Some(stale_participant_cleanup_next_attempt_at(observed_at))
    } else {
        None
    };
    workflow.set_next_attempt_at(next_attempt_at, observed_at);
}

fn stale_participant_cleanup_preflight_passes(
    participant: &CellParticipantRecord,
    self_registration_id: &str,
) -> bool {
    if participant.registration_id == self_registration_id {
        return false;
    }
    let Some(state) = participant.state.as_ref() else {
        return false;
    };
    state.lease.freshness == LeaseFreshness::Expired
        && state.drain_intent == LeaseDrainIntent::Draining
}

fn set_stale_participant_cleanup_step_state(
    workflow: &mut WorkflowInstance<StaleParticipantCleanupWorkflowState>,
    step_index: usize,
    state: WorkflowStepState,
    detail: &'static str,
) {
    if let Some(step) = workflow.step_mut(step_index) {
        step.transition(state, Some(String::from(detail)));
    }
}

fn advance_stale_participant_cleanup_workflow(
    workflow: &mut WorkflowInstance<StaleParticipantCleanupWorkflowState>,
    participant: &CellParticipantRecord,
    self_registration_id: &str,
    observed_at: OffsetDateTime,
) {
    // The local cleanup workflow advances through `review ->
    // preflight_confirmed -> tombstone_eligible`. It proves repeated stale
    // observations first; actual destructive deletion remains deferred to the
    // later tombstone/deletion path outside this helper.
    if !stale_participant_cleanup_preflight_passes(participant, self_registration_id) {
        return;
    }

    if workflow.state.review_observations >= STALE_PARTICIPANT_TOMBSTONE_ELIGIBILITY_OBSERVATIONS {
        workflow
            .state
            .prepare_evacuation_artifacts(self_registration_id, observed_at);
        workflow.state.mark_tombstone_eligible(observed_at);
        workflow.current_step_index = Some(STALE_PARTICIPANT_TOMBSTONE_STEP_INDEX);
        set_stale_participant_cleanup_step_state(
            workflow,
            STALE_PARTICIPANT_REVIEW_STEP_INDEX,
            WorkflowStepState::Completed,
            "stale peer remained expired across repeated local reconciliation",
        );
        set_stale_participant_cleanup_step_state(
            workflow,
            STALE_PARTICIPANT_PREFLIGHT_STEP_INDEX,
            WorkflowStepState::Completed,
            "local preflight confirmed the peer remained expired and draining",
        );
        set_stale_participant_cleanup_step_state(
            workflow,
            STALE_PARTICIPANT_TOMBSTONE_STEP_INDEX,
            WorkflowStepState::Active,
            "peer is locally tombstone-eligible; destructive deletion remains deferred",
        );
        workflow.set_phase(WorkflowPhase::Running);
        return;
    }

    if workflow.state.review_observations >= STALE_PARTICIPANT_PREFLIGHT_CONFIRMATION_OBSERVATIONS {
        workflow
            .state
            .prepare_evacuation_artifacts(self_registration_id, observed_at);
        workflow.state.mark_preflight_confirmed(observed_at);
        workflow.current_step_index = Some(STALE_PARTICIPANT_PREFLIGHT_STEP_INDEX);
        set_stale_participant_cleanup_step_state(
            workflow,
            STALE_PARTICIPANT_REVIEW_STEP_INDEX,
            WorkflowStepState::Completed,
            "stale peer remained expired across repeated local reconciliation",
        );
        set_stale_participant_cleanup_step_state(
            workflow,
            STALE_PARTICIPANT_PREFLIGHT_STEP_INDEX,
            WorkflowStepState::Active,
            "local preflight confirmed the peer remained expired and draining",
        );
        workflow.set_phase(WorkflowPhase::Running);
    }
}

fn participant_reconciliation_state_at(
    participant: &CellParticipantRecord,
    previous: Option<&CellParticipantReconciliationState>,
    observed_at: OffsetDateTime,
) -> Option<CellParticipantReconciliationState> {
    let state = participant.state.as_ref()?;
    let stale_since = match state.lease.freshness {
        LeaseFreshness::Fresh => None,
        LeaseFreshness::Stale | LeaseFreshness::Expired => previous
            .and_then(|reconciliation| reconciliation.stale_since)
            .or(Some(observed_at)),
    };
    let mut reconciliation = CellParticipantReconciliationState::new(observed_at);
    if let Some(stale_since) = stale_since {
        reconciliation = reconciliation.with_stale_since(stale_since);
    }
    if !matches!(state.lease.freshness, LeaseFreshness::Fresh)
        && let Some(cleanup_workflow_id) =
            previous.and_then(|reconciliation| reconciliation.cleanup_workflow_id.clone())
    {
        reconciliation = reconciliation.with_cleanup_workflow_id(cleanup_workflow_id);
    }
    Some(reconciliation)
}

fn stale_participant_cleanup_stale_since(
    participant: &CellParticipantRecord,
    previous: Option<&CellParticipantReconciliationState>,
    self_registration_id: &str,
    observed_at: OffsetDateTime,
) -> Option<OffsetDateTime> {
    if participant.registration_id == self_registration_id {
        return None;
    }
    let state = participant.state.as_ref()?;
    if state.lease.freshness != LeaseFreshness::Expired {
        return None;
    }

    let stale_since = previous
        .and_then(|reconciliation| reconciliation.stale_since)
        .unwrap_or(observed_at);
    let repeated_stale = previous.is_some_and(|reconciliation| {
        reconciliation.stale_since.is_some() && reconciliation.last_reconciled_at < observed_at
    });
    let bounded_stale = observed_at - stale_since
        >= stale_participant_cleanup_threshold(state.lease.duration_seconds);
    if repeated_stale || bounded_stale {
        Some(stale_since)
    } else {
        None
    }
}

async fn upsert_stale_participant_cleanup_workflow(
    workflow_store: &WorkflowCollection<StaleParticipantCleanupWorkflowState>,
    workflow_documents: &mut BTreeMap<
        String,
        StoredDocument<WorkflowInstance<StaleParticipantCleanupWorkflowState>>,
    >,
    cell_id: &str,
    participant: &CellParticipantRecord,
    self_registration_id: &str,
    stale_since: OffsetDateTime,
    observed_at: OffsetDateTime,
) -> Result<WorkflowInstance<StaleParticipantCleanupWorkflowState>> {
    let workflow_id =
        stale_participant_cleanup_workflow_id(cell_id, participant.registration_id.as_str());
    let mut desired =
        stale_participant_cleanup_workflow(cell_id, participant, stale_since, observed_at);
    desired.claim_runner_at(
        self_registration_id,
        stale_participant_cleanup_runner_lease_duration(),
        observed_at,
    )?;
    schedule_stale_participant_cleanup_next_attempt(&mut desired, observed_at);

    loop {
        if let Some((version, deleted, existing_workflow)) = workflow_documents
            .get(&workflow_id)
            .map(|stored| (stored.version, stored.deleted, stored.value.clone()))
        {
            let reset_workflow = deleted || existing_workflow.state.stale_since != stale_since;
            if !deleted
                && stale_participant_cleanup_workflow_claimed_by_other_runner(
                    &existing_workflow,
                    self_registration_id,
                    observed_at,
                )
            {
                return Ok(existing_workflow);
            }

            let mut workflow = if reset_workflow {
                desired.clone()
            } else {
                existing_workflow
            };
            if !reset_workflow && !stale_participant_cleanup_workflow_has_follow_up(&workflow) {
                return Ok(workflow);
            }

            workflow.claim_runner_at(
                self_registration_id,
                stale_participant_cleanup_runner_lease_duration(),
                observed_at,
            )?;
            if !reset_workflow && workflow.is_due_at(observed_at) {
                workflow
                    .state
                    .refresh(cell_id, participant, stale_since, observed_at);
                workflow.state.note_stale_observation(observed_at);
                advance_stale_participant_cleanup_workflow(
                    &mut workflow,
                    participant,
                    self_registration_id,
                    observed_at,
                );
                schedule_stale_participant_cleanup_next_attempt(&mut workflow, observed_at);
            }

            match workflow_store
                .upsert(workflow_id.as_str(), workflow, Some(version))
                .await
            {
                Ok(stored) => {
                    let value = stored.value.clone();
                    workflow_documents.insert(workflow_id.clone(), stored);
                    return Ok(value);
                }
                Err(error) if error.code == ErrorCode::Conflict => {
                    if let Some(stored) = workflow_store.get(workflow_id.as_str()).await? {
                        workflow_documents.insert(workflow_id.clone(), stored);
                        continue;
                    }
                    workflow_documents.remove(&workflow_id);
                    continue;
                }
                Err(error) => return Err(error),
            }
        }

        match workflow_store
            .create(workflow_id.as_str(), desired.clone())
            .await
        {
            Ok(stored) => {
                let value = stored.value.clone();
                workflow_documents.insert(workflow_id.clone(), stored);
                return Ok(value);
            }
            Err(error) if error.code == ErrorCode::Conflict => {
                if let Some(stored) = workflow_store.get(workflow_id.as_str()).await? {
                    workflow_documents.insert(workflow_id.clone(), stored);
                    continue;
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        }
    }
}

async fn reconcile_runtime_stale_participant_cleanup_workflows(
    workflow_store: &WorkflowCollection<StaleParticipantCleanupWorkflowState>,
    cell_directory: &mut CellDirectoryRecord,
    self_registration_id: &str,
    observed_at: OffsetDateTime,
) -> Result<()> {
    let cell_id = cell_directory.cell_id.clone();
    let mut workflow_documents = workflow_store
        .list()
        .await?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let mut participants = Vec::with_capacity(cell_directory.participants.len());

    for participant in cell_directory.participants.clone() {
        let durable_workflow = durable_stale_participant_cleanup_workflow(
            &workflow_documents,
            cell_id.as_str(),
            &participant,
        );
        let previous_reconciliation =
            durable_participant_reconciliation_state(&participant, durable_workflow);
        let cleanup_stale_since = stale_participant_cleanup_stale_since(
            &participant,
            previous_reconciliation.as_ref(),
            self_registration_id,
            observed_at,
        );
        let mut participant = participant;
        participant.reconciliation = participant_reconciliation_state_at(
            &participant,
            previous_reconciliation.as_ref(),
            observed_at,
        );
        if let Some(stale_since) = cleanup_stale_since {
            let workflow = upsert_stale_participant_cleanup_workflow(
                workflow_store,
                &mut workflow_documents,
                cell_id.as_str(),
                &participant,
                self_registration_id,
                stale_since,
                observed_at,
            )
            .await?;
            let reconciliation = participant
                .reconciliation
                .clone()
                .unwrap_or_else(|| CellParticipantReconciliationState::new(observed_at))
                .with_stale_since(stale_since)
                .with_cleanup_workflow_id(workflow.id.clone());
            participant.reconciliation = Some(reconciliation);
        }
        participants.push(participant);
    }

    cell_directory.participants = participants;
    Ok(())
}

async fn list_runtime_stale_participant_cleanup_workflows(
    workflow_store: &WorkflowCollection<StaleParticipantCleanupWorkflowState>,
) -> Result<BTreeMap<String, WorkflowInstance<StaleParticipantCleanupWorkflowState>>> {
    Ok(workflow_store
        .list()
        .await?
        .into_iter()
        .filter_map(|(workflow_id, stored)| {
            (!stored.deleted).then_some((workflow_id, stored.value))
        })
        .collect())
}

async fn list_runtime_participant_tombstone_history(
    history_store: &ParticipantTombstoneHistoryCollection,
) -> Result<Vec<ParticipantTombstoneHistoryRecord>> {
    Ok(
        load_runtime_participant_tombstone_history_snapshot(history_store)
            .await?
            .records,
    )
}

async fn load_runtime_participant_tombstone_history_snapshot(
    history_store: &ParticipantTombstoneHistoryCollection,
) -> Result<RuntimeParticipantTombstoneHistorySnapshot> {
    history_store.reload_from_disk().await?;
    let documents = history_store.list().await?;
    let mut records = documents
        .iter()
        .filter_map(|(_, stored)| (!stored.deleted).then_some(stored.value.clone()))
        .collect::<Vec<_>>();
    records.sort_unstable_by(compare_runtime_participant_tombstone_history_records);
    let oldest_retained = records.last();
    Ok(RuntimeParticipantTombstoneHistorySnapshot {
        retention: RuntimeParticipantTombstoneHistoryRetention {
            max_entries: RUNTIME_TOMBSTONE_HISTORY_RETENTION_LIMIT,
            retained_entries: records.len(),
            pruned_entries: documents
                .iter()
                .filter(|(_, stored)| stored.deleted)
                .count(),
            oldest_retained_tombstoned_at: oldest_retained.map(|record| record.tombstoned_at),
            oldest_retained_event_id: oldest_retained.map(|record| record.event_id.clone()),
        },
        records,
    })
}

async fn load_runtime_participant_tombstone_history_projection(
    history_store: &ParticipantTombstoneHistoryCollection,
    query: &RuntimeParticipantTombstoneHistoryQuery,
) -> Result<RuntimeParticipantTombstoneHistoryProjection> {
    let snapshot = load_runtime_participant_tombstone_history_snapshot(history_store).await?;
    Ok(runtime_participant_tombstone_history_projection(
        &snapshot.records,
        query,
        snapshot.retention,
    ))
}

async fn load_runtime_participant_tombstone_relay_evidence(
    outbox: &DurableEventRelay<PlatformEvent>,
) -> Result<BTreeMap<String, EventRelayEnvelope<PlatformEvent>>> {
    let mut evidence = BTreeMap::new();
    for envelope in outbox.list_all().await?.into_iter() {
        let Some(event_id) = runtime_participant_tombstone_relay_event_id(&envelope) else {
            continue;
        };
        let should_replace = match evidence.get(event_id.as_str()) {
            Some(current) => {
                runtime_participant_tombstone_relay_evidence_is_newer(current, &envelope)
            }
            None => true,
        };
        if should_replace {
            evidence.insert(event_id, envelope);
        }
    }
    Ok(evidence)
}

async fn load_runtime_participant_tombstone_aggregate_projection(
    history_store: &ParticipantTombstoneHistoryCollection,
    outbox: &DurableEventRelay<PlatformEvent>,
    query: &RuntimeParticipantTombstoneAggregateQuery,
) -> Result<RuntimeParticipantTombstoneAggregateProjection> {
    let snapshot = load_runtime_participant_tombstone_history_snapshot(history_store).await?;
    let relay_evidence = load_runtime_participant_tombstone_relay_evidence(outbox).await?;
    Ok(runtime_participant_tombstone_aggregate_projection(
        &snapshot.records,
        &relay_evidence,
        query,
        snapshot.retention,
    ))
}

async fn prune_runtime_participant_tombstone_history(
    history_store: &ParticipantTombstoneHistoryCollection,
) -> Result<RuntimeParticipantTombstoneHistoryRetention> {
    let mut active_documents = history_store
        .list()
        .await?
        .into_iter()
        .filter(|(_, stored)| !stored.deleted)
        .collect::<Vec<_>>();
    active_documents.sort_unstable_by(|left, right| {
        compare_runtime_participant_tombstone_history_records(&left.1.value, &right.1.value)
    });
    for (event_id, stored) in active_documents
        .into_iter()
        .skip(RUNTIME_TOMBSTONE_HISTORY_RETENTION_LIMIT)
    {
        history_store
            .soft_delete(event_id.as_str(), Some(stored.version))
            .await?;
    }
    Ok(
        load_runtime_participant_tombstone_history_snapshot(history_store)
            .await?
            .retention,
    )
}

fn runtime_tombstone_actor(context: &RequestContext) -> AuditActor {
    let actor_subject = context
        .principal
        .as_ref()
        .map(|principal| principal.subject.clone())
        .or_else(|| context.actor.clone())
        .unwrap_or_else(|| String::from("system"));
    let actor_type = context
        .principal
        .as_ref()
        .map(|principal| principal.kind.as_str().to_owned())
        .unwrap_or_else(|| String::from("principal"));
    AuditActor {
        subject: actor_subject,
        actor_type,
        source_ip: None,
        correlation_id: context.correlation_id.clone(),
    }
}

fn runtime_participant_tombstone_event(
    history: &ParticipantTombstoneHistoryRecord,
) -> Result<PlatformEvent> {
    let event_id = AuditId::parse(history.event_id.as_str()).map_err(|error| {
        PlatformError::unavailable("failed to parse runtime tombstone event id")
            .with_detail(error.to_string())
    })?;
    let details = serde_json::to_value(history).map_err(|error| {
        PlatformError::unavailable("failed to encode runtime tombstone event details")
            .with_detail(error.to_string())
    })?;
    Ok(PlatformEvent {
        header: EventHeader {
            event_id,
            event_type: String::from(RUNTIME_PARTICIPANT_TOMBSTONED_EVENT_TYPE),
            schema_version: 1,
            source_service: String::from(RUNTIME_SOURCE_SERVICE),
            emitted_at: history.tombstoned_at,
            actor: AuditActor {
                subject: history.actor_subject.clone(),
                actor_type: history.actor_type.clone(),
                source_ip: None,
                correlation_id: history.correlation_id.clone(),
            },
        },
        payload: EventPayload::Service(ServiceEvent {
            resource_kind: String::from("cell_participant"),
            resource_id: history.participant_registration_id.clone(),
            action: String::from("tombstoned"),
            details,
        }),
    })
}

async fn append_runtime_participant_tombstone_event(
    context: &RuntimeProcessRegistrationContext,
    history: &ParticipantTombstoneHistoryRecord,
) -> Result<()> {
    let event = runtime_participant_tombstone_event(history)?;
    let idempotency = event.header.event_id.to_string();
    context.audit_log.append(&event).await?;
    context
        .outbox
        .publish(
            RelayPublishRequest::new(RUNTIME_EVENTS_TOPIC, event)
                .with_idempotency_key(idempotency)
                .with_source_service(RUNTIME_SOURCE_SERVICE)
                .with_event_type(RUNTIME_PARTICIPANT_TOMBSTONED_EVENT_TYPE),
        )
        .await?;
    Ok(())
}

async fn tombstone_runtime_participant(
    context: &RuntimeProcessRegistrationContext,
    participant_registration_id: &str,
    observed_at: OffsetDateTime,
    request_context: &RequestContext,
) -> Result<TombstoneRuntimeParticipantReply> {
    let participant_registration_id = participant_registration_id.trim();
    if participant_registration_id.is_empty() {
        return Err(PlatformError::invalid(
            "runtime participant registration_id may not be empty",
        ));
    }
    if participant_registration_id == context.publication_plan.registration_key() {
        return Err(PlatformError::forbidden(
            "cannot tombstone current runtime participant",
        ));
    }

    let stored_cell_directory = context
        .cell_directory_store
        .get(context.publication_plan.cell().cell_id.as_str())
        .await?
        .ok_or_else(|| {
            PlatformError::not_found(format!(
                "cell directory `{}` does not exist",
                context.publication_plan.cell().cell_id.as_str()
            ))
        })?;
    if stored_cell_directory.deleted {
        return Err(PlatformError::conflict(format!(
            "cell directory `{}` has already been deleted",
            context.publication_plan.cell().cell_id.as_str()
        )));
    }

    let participant = stored_cell_directory
        .value
        .participants
        .iter()
        .find(|participant| participant.registration_id == participant_registration_id)
        .cloned()
        .ok_or_else(|| {
            PlatformError::not_found(format!(
                "participant `{participant_registration_id}` is not registered in cell `{}`",
                context.publication_plan.cell().cell_id.as_str()
            ))
        })?;
    if !stale_participant_cleanup_preflight_passes(
        &participant,
        context.publication_plan.registration_key(),
    ) {
        return Err(
            PlatformError::conflict("participant is not eligible for tombstone")
                .with_detail("participant must remain expired and draining at mutation time"),
        );
    }

    let cleanup_workflow_id = participant
        .reconciliation
        .as_ref()
        .and_then(|reconciliation| reconciliation.cleanup_workflow_id.clone())
        .ok_or_else(|| PlatformError::conflict("participant has no linked cleanup workflow"))?;
    let stored_workflow = context
        .cleanup_workflow_store
        .get(cleanup_workflow_id.as_str())
        .await?
        .ok_or_else(|| PlatformError::conflict("participant cleanup workflow does not exist"))?;
    if stored_workflow.deleted {
        return Err(PlatformError::conflict(
            "participant cleanup workflow has already been deleted",
        ));
    }
    if !runtime_participant_cleanup_workflow_is_tombstone_eligible(
        &stored_workflow.value,
        context.publication_plan.cell().cell_id.as_str(),
        &participant,
    ) {
        return Err(PlatformError::conflict(
            "participant cleanup workflow is not tombstone-eligible",
        )
        .with_detail(
            "re-run bounded stale-participant review until the workflow reaches tombstone_eligible",
        ));
    }

    let mut updated_cell_directory = stored_cell_directory.value.clone();
    if !updated_cell_directory.remove_participant(participant.registration_id.as_str()) {
        return Err(PlatformError::not_found(format!(
            "participant `{participant_registration_id}` is not registered in cell `{}`",
            context.publication_plan.cell().cell_id.as_str()
        )));
    }
    context
        .cell_directory_store
        .upsert(
            context.publication_plan.cell().cell_id.as_str(),
            updated_cell_directory,
            Some(stored_cell_directory.version),
        )
        .await?;

    let lease_registration_id = participant.lease_registration_id.clone();
    let mut lease_registration_soft_deleted = false;
    if let Some(lease_registration_id) = lease_registration_id.as_deref()
        && let Some(stored_registration) = context.store.get(lease_registration_id).await?
        && !stored_registration.deleted
    {
        context
            .store
            .soft_delete(lease_registration_id, Some(stored_registration.version))
            .await?;
        lease_registration_soft_deleted = true;
    }

    let mut completed_workflow = stored_workflow.value.clone();
    completed_workflow.current_step_index = Some(2);
    set_stale_participant_cleanup_step_state(
        &mut completed_workflow,
        0,
        WorkflowStepState::Completed,
        "stale peer remained expired across repeated local reconciliation",
    );
    set_stale_participant_cleanup_step_state(
        &mut completed_workflow,
        1,
        WorkflowStepState::Completed,
        "local preflight confirmed the peer remained expired and draining",
    );
    set_stale_participant_cleanup_step_state(
        &mut completed_workflow,
        2,
        WorkflowStepState::Completed,
        "operator-approved tombstone removed the stale participant from the local cell directory",
    );
    completed_workflow.set_phase(WorkflowPhase::Completed);
    let completed_workflow = context
        .cleanup_workflow_store
        .upsert(
            cleanup_workflow_id.as_str(),
            completed_workflow,
            Some(stored_workflow.version),
        )
        .await?;
    let event_id = AuditId::generate().map_err(|error| {
        PlatformError::unavailable("failed to allocate runtime tombstone history id")
            .with_detail(error.to_string())
    })?;
    let actor = runtime_tombstone_actor(request_context);
    let history = ParticipantTombstoneHistoryRecord::new(
        event_id.to_string(),
        &participant,
        cleanup_workflow_id.clone(),
        observed_at,
        actor.subject.clone(),
        actor.actor_type.clone(),
        actor.correlation_id.clone(),
    )
    .with_cell_context(
        stored_cell_directory.value.cell_id.clone(),
        stored_cell_directory.value.cell_name.clone(),
        &stored_cell_directory.value.region,
    )
    .with_cleanup_review(
        completed_workflow.value.state.review_observations,
        completed_workflow.value.state.stale_since,
        completed_workflow.value.state.preflight_confirmed_at,
        completed_workflow.value.state.tombstone_eligible_at,
    )
    .with_mutation_result(true, lease_registration_soft_deleted, false);
    let history_event_id = history.event_id.clone();
    let stored_history = context
        .tombstone_history_store
        .create(history_event_id.as_str(), history)
        .await?;
    context
        .cleanup_workflow_store
        .soft_delete(
            cleanup_workflow_id.as_str(),
            Some(completed_workflow.version),
        )
        .await?;

    let final_history = context
        .tombstone_history_store
        .upsert(
            stored_history.value.event_id.as_str(),
            stored_history.value.clone().with_mutation_result(
                true,
                lease_registration_soft_deleted,
                true,
            ),
            Some(stored_history.version),
        )
        .await?
        .value;

    append_runtime_participant_tombstone_event(context, &final_history).await?;
    prune_runtime_participant_tombstone_history(&context.tombstone_history_store).await?;

    context.publish_current_topology(observed_at).await?;

    Ok(TombstoneRuntimeParticipantReply {
        cell_id: context.publication_plan.cell().cell_id.clone(),
        participant_registration_id: participant.registration_id,
        cleanup_workflow_id,
        tombstoned_at: observed_at,
        lease_registration_id,
        removed_from_cell_directory: true,
        lease_registration_soft_deleted,
        cleanup_workflow_soft_deleted: true,
    })
}

async fn activate_runtime_cell_directory(
    store: &CellDirectoryCollection,
    registration_store: &LeaseRegistrationCollection,
    cleanup_workflow_store: &WorkflowCollection<StaleParticipantCleanupWorkflowState>,
    registry_reconciler: &RuntimeRegistryReconciler,
    registration: &LeaseRegistrationRecord,
    observed_at: OffsetDateTime,
) -> Result<CellDirectoryRecord> {
    registry_reconciler
        .reconcile_cell_directory(
            store,
            registration_store,
            cleanup_workflow_store,
            registration,
            observed_at,
        )
        .await
}

async fn persist_runtime_service_group_directory(
    store: &CellServiceGroupDirectoryCollection,
    cell_directory: &CellDirectoryRecord,
) -> Result<()> {
    let record = resolve_cell_service_group_directory(cell_directory);
    let expected_version = store
        .get(cell_directory.cell_id.as_str())
        .await?
        .map(|stored| stored.version);
    store
        .upsert(cell_directory.cell_id.as_str(), record, expected_version)
        .await?;
    Ok(())
}

async fn activate_runtime_registration(
    store: &LeaseRegistrationCollection,
    publication_plan: &RuntimeRolePublicationPlan,
) -> Result<LeaseRegistrationRecord> {
    let record = LeaseRegistrationRecord::new(
        publication_plan.registration_key(),
        RUNTIME_PROCESS_SUBJECT_KIND,
        publication_plan.registration_key(),
        publication_plan.process_role().as_str(),
        Some(publication_plan.node_name().to_owned()),
        RUNTIME_PROCESS_LEASE_DURATION_SECONDS,
    )
    .with_readiness(LeaseReadiness::Ready)
    .with_drain_intent(LeaseDrainIntent::Serving);
    Ok(store
        .claim_incarnation(publication_plan.registration_key(), record)
        .await?
        .value)
}

#[cfg(test)]
async fn mutate_runtime_registration<F>(
    store: &LeaseRegistrationCollection,
    registration_key: &str,
    mut mutate: F,
) -> Result<Option<LeaseRegistrationRecord>>
where
    F: FnMut(&mut LeaseRegistrationRecord),
{
    let Some(stored) = store.get(registration_key).await? else {
        return Ok(None);
    };
    let mut record = stored.value;
    mutate(&mut record);
    Ok(Some(
        store
            .upsert(registration_key, record, Some(stored.version))
            .await?
            .value,
    ))
}

#[derive(Debug, Clone)]
struct RuntimeProcessRegistrationContext {
    store: LeaseRegistrationCollection,
    cell_directory_store: CellDirectoryCollection,
    service_group_directory_store: CellServiceGroupDirectoryCollection,
    cleanup_workflow_store: WorkflowCollection<StaleParticipantCleanupWorkflowState>,
    registry_reconciler: RuntimeRegistryReconciler,
    tombstone_history_store: ParticipantTombstoneHistoryCollection,
    audit_log: AuditLog,
    outbox: DurableEventRelay<PlatformEvent>,
    publication_plan: RuntimeRolePublicationPlan,
    topology_handle: RuntimeTopologyHandle,
    readyz_handle: RuntimeReadyzHandle,
    current_fencing_token: Arc<Mutex<String>>,
}

impl RuntimeProcessRegistrationContext {
    fn capture_readyz_failure<T>(
        &self,
        reason: RuntimeReadyzFailureReason,
        result: Result<T>,
    ) -> Result<T> {
        result.inspect_err(|error| {
            self.readyz_handle.fail(reason, error.to_string());
        })
    }

    fn current_fencing_token(&self) -> String {
        self.current_fencing_token
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    fn replace_fencing_token(&self, fencing_token: &str) {
        *self
            .current_fencing_token
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = fencing_token.to_owned();
    }

    async fn publish(
        &self,
        registration: &LeaseRegistrationRecord,
        cell_directory: &CellDirectoryRecord,
        observed_at: OffsetDateTime,
    ) -> Result<()> {
        let service_group_directory = resolve_cell_service_group_directory(cell_directory);
        let cleanup_workflows = self.capture_readyz_failure(
            RuntimeReadyzFailureReason::TopologyPublicationFailed,
            list_runtime_stale_participant_cleanup_workflows(&self.cleanup_workflow_store).await,
        )?;
        let tombstone_history = self.capture_readyz_failure(
            RuntimeReadyzFailureReason::TopologyPublicationFailed,
            list_runtime_participant_tombstone_history(&self.tombstone_history_store).await,
        )?;
        self.topology_handle
            .replace(self.publication_plan.publish_topology(
                registration,
                cell_directory,
                &service_group_directory,
                &cleanup_workflows,
                &tombstone_history,
                observed_at,
            ));
        self.readyz_handle.clear_failure();
        Ok(())
    }

    async fn reconcile_cell_directory(
        &self,
        registration: &LeaseRegistrationRecord,
        observed_at: OffsetDateTime,
    ) -> Result<CellDirectoryRecord> {
        let cell_directory = activate_runtime_cell_directory(
            &self.cell_directory_store,
            &self.store,
            &self.cleanup_workflow_store,
            &self.registry_reconciler,
            registration,
            observed_at,
        )
        .await?;
        persist_runtime_service_group_directory(
            &self.service_group_directory_store,
            &cell_directory,
        )
        .await?;
        Ok(cell_directory)
    }

    async fn publish_current_topology(&self, observed_at: OffsetDateTime) -> Result<()> {
        let registration = self
            .capture_readyz_failure(
                RuntimeReadyzFailureReason::TopologyPublicationFailed,
                self.store
                    .get(self.publication_plan.registration_key())
                    .await,
            )?
            .filter(|stored| !stored.deleted)
            .map(|stored| stored.value)
            .ok_or_else(|| {
                PlatformError::not_found(format!(
                    "runtime registration `{}` does not exist",
                    self.publication_plan.registration_key()
                ))
            });
        let registration = self.capture_readyz_failure(
            RuntimeReadyzFailureReason::TopologyPublicationFailed,
            registration,
        )?;
        let cell_directory = self
            .capture_readyz_failure(
                RuntimeReadyzFailureReason::TopologyPublicationFailed,
                self.cell_directory_store
                    .get(self.publication_plan.cell().cell_id.as_str())
                    .await,
            )?
            .filter(|stored| !stored.deleted)
            .map(|stored| stored.value)
            .ok_or_else(|| {
                PlatformError::not_found(format!(
                    "cell directory `{}` does not exist",
                    self.publication_plan.cell().cell_id.as_str()
                ))
            });
        let cell_directory = self.capture_readyz_failure(
            RuntimeReadyzFailureReason::TopologyPublicationFailed,
            cell_directory,
        )?;
        self.capture_readyz_failure(
            RuntimeReadyzFailureReason::TopologyPublicationFailed,
            persist_runtime_service_group_directory(
                &self.service_group_directory_store,
                &cell_directory,
            )
            .await,
        )?;
        self.capture_readyz_failure(
            RuntimeReadyzFailureReason::TopologyPublicationFailed,
            self.publish(&registration, &cell_directory, observed_at)
                .await,
        )
    }

    async fn renew(&self) -> Result<()> {
        if let Some(store) = self.store.local_document_store() {
            self.capture_readyz_failure(
                RuntimeReadyzFailureReason::LeaseRenewalFailed,
                store.reload_from_disk().await,
            )?;
        }
        let fencing_token = self.current_fencing_token();
        if let Some(registration) = self.capture_readyz_failure(
            RuntimeReadyzFailureReason::LeaseRenewalFailed,
            self.store
                .fenced_mutate(
                    self.publication_plan.registration_key(),
                    fencing_token.as_str(),
                    |registration| {
                        registration.set_readiness(LeaseReadiness::Ready);
                        registration.set_drain_intent(LeaseDrainIntent::Serving);
                        registration.renew();
                    },
                )
                .await,
        )? {
            let registration = registration.value;
            self.replace_fencing_token(registration.fencing_token.as_str());
            let observed_at = OffsetDateTime::now_utc();
            let cell_directory = self.capture_readyz_failure(
                RuntimeReadyzFailureReason::LeaseRenewalFailed,
                self.reconcile_cell_directory(&registration, observed_at)
                    .await,
            )?;
            self.publish(&registration, &cell_directory, observed_at)
                .await?;
            return Ok(());
        }

        let registration = self.capture_readyz_failure(
            RuntimeReadyzFailureReason::LeaseRenewalFailed,
            activate_runtime_registration(&self.store, &self.publication_plan).await,
        )?;
        self.replace_fencing_token(registration.fencing_token.as_str());
        let observed_at = OffsetDateTime::now_utc();
        let cell_directory = self.capture_readyz_failure(
            RuntimeReadyzFailureReason::LeaseRenewalFailed,
            self.reconcile_cell_directory(&registration, observed_at)
                .await,
        )?;
        self.publish(&registration, &cell_directory, observed_at)
            .await?;
        Ok(())
    }

    async fn request_drain(&self) -> Result<()> {
        let fencing_token = self.current_fencing_token();
        if let Some(registration) = self
            .store
            .fenced_mutate(
                self.publication_plan.registration_key(),
                fencing_token.as_str(),
                |registration| {
                    registration.set_drain_intent(LeaseDrainIntent::Draining);
                },
            )
            .await?
        {
            let registration = registration.value;
            self.replace_fencing_token(registration.fencing_token.as_str());
            let observed_at = OffsetDateTime::now_utc();
            let cell_directory = self
                .reconcile_cell_directory(&registration, observed_at)
                .await?;
            self.publish(&registration, &cell_directory, observed_at)
                .await?;
        }
        Ok(())
    }

    async fn renew_forever(self) {
        let mut interval = tokio::time::interval(RUNTIME_PROCESS_LEASE_RENEW_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            let _ = self.renew().await;
        }
    }
}

#[derive(Debug, Clone)]
struct RuntimeOperatorService {
    registration_context: RuntimeProcessRegistrationContext,
}

impl RuntimeOperatorService {
    fn new(registration_context: RuntimeProcessRegistrationContext) -> Self {
        Self {
            registration_context,
        }
    }

    async fn list_aggregated_tombstone_history(
        &self,
        query: &BTreeMap<String, String>,
    ) -> Result<Response<ApiBody>> {
        let query = parse_runtime_participant_tombstone_aggregate_query(query)?;
        let projection = load_runtime_participant_tombstone_aggregate_projection(
            &self.registration_context.tombstone_history_store,
            &self.registration_context.outbox,
            &query,
        )
        .await?;
        json_response(StatusCode::OK, &projection)
    }

    async fn list_tombstone_history(
        &self,
        query: &BTreeMap<String, String>,
    ) -> Result<Response<ApiBody>> {
        let query = parse_runtime_participant_tombstone_history_query(query)?;
        let projection = load_runtime_participant_tombstone_history_projection(
            &self.registration_context.tombstone_history_store,
            &query,
        )
        .await?;
        json_response(StatusCode::OK, &projection)
    }

    async fn tombstone_participant(
        &self,
        request: TombstoneRuntimeParticipantRequest,
        context: RequestContext,
    ) -> Result<Response<ApiBody>> {
        let reply = tombstone_runtime_participant(
            &self.registration_context,
            request.registration_id.as_str(),
            OffsetDateTime::now_utc(),
            &context,
        )
        .await?;
        json_response(StatusCode::OK, &reply)
    }
}

impl HttpService for RuntimeOperatorService {
    fn name(&self) -> &'static str {
        "runtime-operator"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] = &[
            uhost_runtime::RouteClaim::exact("/runtime/participants/tombstone"),
            uhost_runtime::RouteClaim::exact("/runtime/participants/tombstone-history"),
            uhost_runtime::RouteClaim::exact("/runtime/participants/tombstone-history/aggregated"),
        ];
        ROUTE_CLAIMS
    }

    fn handle<'a>(
        &'a self,
        request: Request<uhost_runtime::RequestBody>,
        context: uhost_core::RequestContext,
    ) -> uhost_runtime::ResponseFuture<'a> {
        Box::pin(async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let query = parse_query(request.uri().query());
            let segments = path_segments(path.as_str());
            match (method, segments.as_slice()) {
                (Method::GET, ["runtime", "participants", "tombstone-history", "aggregated"]) => {
                    self.list_aggregated_tombstone_history(&query)
                        .await
                        .map(Some)
                }
                (Method::GET, ["runtime", "participants", "tombstone-history"]) => {
                    self.list_tombstone_history(&query).await.map(Some)
                }
                (Method::POST, ["runtime", "participants", "tombstone"]) => {
                    let body: TombstoneRuntimeParticipantRequest = parse_json(request).await?;
                    self.tombstone_participant(body, context).await.map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

#[derive(Debug, Clone, Serialize)]
struct RuntimeInternalRouteCatalogEntry {
    claim: &'static str,
    match_kind: &'static str,
    method_match: &'static str,
    request_class: &'static str,
    audience: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct RuntimeInternalRouteCatalog {
    service: &'static str,
    bindings: Vec<RuntimeInternalRouteCatalogEntry>,
}

#[derive(Debug, Clone)]
struct RuntimeInternalService {
    registration_context: RuntimeProcessRegistrationContext,
}

impl RuntimeInternalService {
    fn new(registration_context: RuntimeProcessRegistrationContext) -> Self {
        Self {
            registration_context,
        }
    }

    fn route_catalog(&self) -> RuntimeInternalRouteCatalog {
        RuntimeInternalRouteCatalog {
            service: self.name(),
            bindings: RUNTIME_INTERNAL_ROUTE_SURFACES
                .iter()
                .copied()
                .map(|binding| RuntimeInternalRouteCatalogEntry {
                    claim: binding.path(),
                    match_kind: binding.match_kind(),
                    method_match: binding.method_match().as_str(),
                    request_class: binding.request_class().as_str(),
                    audience: RUNTIME_INTERNAL_ROUTE_AUDIENCES
                        .iter()
                        .copied()
                        .find(|audience| audience.path() == binding.path())
                        .map(|audience| audience.audience())
                        .unwrap_or_else(|| {
                            panic!(
                                "internal runtime route `{}` missing audience binding",
                                binding.path()
                            )
                        }),
                })
                .collect(),
        }
    }

    fn list_routes(&self) -> Result<Response<ApiBody>> {
        json_response(StatusCode::OK, &self.route_catalog())
    }

    fn topology(&self) -> Result<Response<ApiBody>> {
        json_response(
            StatusCode::OK,
            &self.registration_context.topology_handle.snapshot(),
        )
    }
}

impl HttpService for RuntimeInternalService {
    fn name(&self) -> &'static str {
        "runtime-internal"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] = &[
            uhost_runtime::RouteClaim::exact("/internal/runtime/routes"),
            uhost_runtime::RouteClaim::exact("/internal/runtime/topology"),
        ];
        ROUTE_CLAIMS
    }

    fn handle<'a>(
        &'a self,
        request: Request<uhost_runtime::RequestBody>,
        _context: uhost_core::RequestContext,
    ) -> uhost_runtime::ResponseFuture<'a> {
        Box::pin(async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let segments = path_segments(path.as_str());
            match (method, segments.as_slice()) {
                (Method::GET, ["internal", "runtime", "routes"]) => self.list_routes().map(Some),
                (Method::GET, ["internal", "runtime", "topology"]) => self.topology().map(Some),
                _ => Ok(None),
            }
        })
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
struct PlacementConfig {
    #[serde(default)]
    region_name: Option<String>,
    #[serde(default)]
    cell_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AllInOneConfig {
    schema: ConfigSchema,
    listen: String,
    state_dir: String,
    #[serde(default)]
    secrets: SecretsConfig,
    #[serde(default)]
    security: SecurityConfig,
    #[serde(default)]
    placement: PlacementConfig,
    #[serde(default)]
    runtime: RuntimeConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct SecretsConfig {
    master_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct SecurityConfig {
    bootstrap_admin_token: Option<SecretString>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RuntimeConfig {
    process_role: Option<String>,
    #[serde(default)]
    forward_targets: BTreeMap<String, String>,
}

fn is_placeholder_bootstrap_token(token: &str) -> bool {
    token.to_ascii_lowercase().contains("change-me")
}

fn contains_placeholder_secret_marker(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "change-me",
        "placeholder",
        "example",
        "sample",
        "dummy",
        "replace-me",
        "replace_this",
        "replace-this",
        "insecure",
        "master-key-material",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn decodes_to_human_readable_secret(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|byte| matches!(*byte, b' '..=b'~'))
}

fn parse_listen_address(listen: &str) -> Result<SocketAddr> {
    listen.parse::<SocketAddr>().map_err(|error| {
        PlatformError::invalid("listen must be a valid socket address")
            .with_detail(error.to_string())
    })
}

fn normalize_topology_label(value: &str, field_name: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(format!(
            "{field_name} may not be empty"
        )));
    }
    if normalized.len() > MAX_TOPOLOGY_LABEL_LEN {
        return Err(PlatformError::invalid(format!("{field_name} is too long")));
    }
    if normalized.chars().all(|character| {
        character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
    }) {
        Ok(normalized)
    } else {
        Err(PlatformError::invalid(format!(
            "{field_name} may only contain lowercase ASCII letters, digits, and hyphens"
        )))
    }
}

fn runtime_process_role_requires_non_local_manifests(process_role: RuntimeProcessRole) -> bool {
    matches!(
        process_role,
        RuntimeProcessRole::Edge | RuntimeProcessRole::Worker | RuntimeProcessRole::NodeAdjacent
    )
}

fn validate_runtime_startup_admission(
    process_role: RuntimeProcessRole,
    forward_targets: &BTreeMap<String, SocketAddr>,
) -> Result<()> {
    if runtime_process_role_requires_non_local_manifests(process_role) && forward_targets.is_empty()
    {
        return Err(PlatformError::invalid(format!(
            "runtime.process_role `{}` may not activate with only local manifests",
            process_role.as_str()
        ))
        .with_detail(
            "configure runtime.forward_targets for at least one non-local service family owned by another role",
        ));
    }

    Ok(())
}

impl AllInOneConfig {
    fn master_key_value(&self) -> Option<&str> {
        self.secrets
            .master_key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn bootstrap_admin_token_value(&self) -> Option<&str> {
        self.security
            .bootstrap_admin_token
            .as_ref()
            .map(|token| token.expose().trim())
            .filter(|token| !token.is_empty())
    }

    fn runtime_process_role(&self) -> Result<RuntimeProcessRole> {
        let Some(configured_process_role) = self
            .runtime
            .process_role
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(RuntimeProcessRole::AllInOne);
        };

        let process_role = parse_runtime_process_role(configured_process_role).ok_or_else(|| {
            let supported_roles = supported_runtime_process_role_names()
                .collect::<Vec<_>>()
                .join(", ");
            PlatformError::invalid(format!(
                "runtime.process_role `{configured_process_role}` is invalid; expected one of {supported_roles}"
            ))
        })?;
        Ok(process_role)
    }

    fn runtime_cell_placement(&self) -> Result<RuntimeCellPlacement> {
        let region_name = self.placement.region_name.as_deref().map_or_else(
            || Ok(String::from(DEFAULT_LOCAL_REGION_NAME)),
            |value| normalize_topology_label(value, "placement.region_name"),
        )?;
        let cell_name = self.placement.cell_name.as_deref().map_or_else(
            || Ok(String::from(DEFAULT_LOCAL_CELL_NAME)),
            |value| normalize_topology_label(value, "placement.cell_name"),
        )?;
        Ok(RuntimeCellPlacement::new(region_name, cell_name))
    }

    fn requires_operator_managed_secrets(&self, address: &SocketAddr) -> bool {
        self.schema.mode != ServiceMode::AllInOne || !address.ip().is_loopback()
    }

    fn runtime_access_config(&self, address: &SocketAddr) -> RuntimeAccessConfig {
        // Auth policy is intentionally narrow: a configured bootstrap token is
        // always honored, and unauthenticated local-dev service routes are only
        // enabled for loopback all-in-one startup when no bootstrap token is
        // present.
        let base_access = match self.security.bootstrap_admin_token.clone() {
            Some(token) => RuntimeAccessConfig::default().with_bootstrap_admin_token(token),
            None => RuntimeAccessConfig::default(),
        };

        if !self.requires_operator_managed_secrets(address)
            && self.bootstrap_admin_token_value().is_none()
        {
            return base_access.with_unauthenticated_local_dev_service_routes();
        }

        base_access
    }

    fn runtime_forward_targets(
        &self,
        publication_plan: &RuntimeRolePublicationPlan,
        listen_address: &SocketAddr,
    ) -> Result<BTreeMap<String, SocketAddr>> {
        let mut forward_targets = BTreeMap::new();
        for (service_name, address) in &self.runtime.forward_targets {
            let service_name = service_name.trim();
            if service_name.is_empty() {
                return Err(PlatformError::invalid(
                    "runtime.forward_targets keys may not be empty",
                ));
            }

            let target = address.trim().parse::<SocketAddr>().map_err(|error| {
                PlatformError::invalid(format!(
                    "runtime.forward_targets.{service_name} must be a valid socket address"
                ))
                .with_detail(error.to_string())
            })?;
            if target == *listen_address {
                return Err(PlatformError::invalid(format!(
                    "runtime.forward_targets.{service_name} may not target the current listen address"
                )));
            }

            forward_targets.insert(service_name.to_owned(), target);
        }

        let _ = publication_plan
            .forwarded_service_registrations(forward_targets.keys().map(String::as_str))?;
        Ok(forward_targets)
    }
}

impl LoadableConfig for AllInOneConfig {
    fn validate(&self) -> Result<()> {
        let address = parse_listen_address(&self.listen)?;

        if self.state_dir.trim().is_empty() {
            return Err(PlatformError::invalid("state_dir may not be empty"));
        }

        if self.schema.node_name.trim().is_empty() {
            return Err(PlatformError::invalid("schema.node_name may not be empty"));
        }

        let process_role = self.runtime_process_role()?;
        if process_role != RuntimeProcessRole::AllInOne && self.schema.mode == ServiceMode::AllInOne
        {
            return Err(PlatformError::invalid(
                "runtime.process_role may only be non-all_in_one when schema.mode is single_node or distributed",
            ));
        }

        let _ = self.runtime_cell_placement()?;
        let publication_plan = runtime_role_publication_plan(self)?;
        let forward_targets = self.runtime_forward_targets(&publication_plan, &address)?;
        validate_runtime_startup_admission(process_role, &forward_targets)?;

        let master_key = self
            .master_key_value()
            .ok_or_else(|| PlatformError::invalid("secrets.master_key is required"))?;
        let bytes = base64url_decode(master_key)?;
        if bytes.len() != 32 {
            return Err(PlatformError::invalid(
                "secrets.master_key must decode to 32 bytes",
            ));
        }

        let requires_operator_managed_secrets = self.requires_operator_managed_secrets(&address);
        if requires_operator_managed_secrets
            && (contains_placeholder_secret_marker(master_key)
                || decodes_to_human_readable_secret(&bytes))
        {
            return Err(PlatformError::invalid(
                "secrets.master_key must be unique deployment-specific key material",
            )
            .with_detail(
                "set UHOST_SECRETS__MASTER_KEY to a base64url-encoded 32-byte random key",
            ));
        }

        if let Some(token) = self.security.bootstrap_admin_token.as_ref()
            && token.expose().trim().is_empty()
        {
            return Err(PlatformError::invalid(
                "security.bootstrap_admin_token may not be empty when configured",
            ));
        }
        let bootstrap_token = self.bootstrap_admin_token_value();

        if requires_operator_managed_secrets && bootstrap_token.is_none() {
            return Err(PlatformError::invalid(
                "security.bootstrap_admin_token is required for externally reachable or non-all_in_one deployments",
            ));
        }

        if let Some(token) = bootstrap_token
            && requires_operator_managed_secrets
        {
            if is_placeholder_bootstrap_token(token) || contains_placeholder_secret_marker(token) {
                return Err(PlatformError::invalid(
                    "security.bootstrap_admin_token placeholder value is not allowed",
                )
                .with_detail("configure a unique non-placeholder token before startup"));
            }

            if token.len() < MIN_BOOTSTRAP_ADMIN_TOKEN_LEN {
                return Err(PlatformError::invalid(
                    "security.bootstrap_admin_token must be at least 32 characters in production posture",
                )
                .with_detail(
                    "set UHOST_SECURITY__BOOTSTRAP_ADMIN_TOKEN to a long unique bootstrap token",
                ));
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = parse_config_path()?;
    let config: AllInOneConfig = ConfigLoader::new("UHOST").load(config_path).await?;
    let address = parse_listen_address(&config.listen)?;
    let state_dir = PathBuf::from(&config.state_dir);
    let publication_plan = runtime_role_publication_plan(&config)?;
    let forward_targets = config.runtime_forward_targets(&publication_plan, &address)?;
    let forwarded_services = publication_plan
        .forwarded_service_registrations(forward_targets.keys().map(String::as_str))?;
    let master_key = config
        .master_key_value()
        .ok_or_else(|| PlatformError::invalid("secrets.master_key is required"))?;
    let secrets_key = SecretBytes::new(base64url_decode(master_key)?);
    let identity_service =
        Arc::new(IdentityService::open_with_master_key(&state_dir, secrets_key.clone()).await?);

    let access = config
        .runtime_access_config(&address)
        .with_bearer_token_authorizer(identity_service.clone());
    let registration_store =
        LeaseRegistrationCollection::open_local(runtime_registration_store_path(&state_dir))
            .await?;
    let registration_housekeeping_task = registration_store.spawn_local_housekeeping()?;
    let cell_directory_store =
        CellDirectoryCollection::open_local(runtime_cell_directory_store_path(&state_dir)).await?;
    let service_group_directory_store = CellServiceGroupDirectoryCollection::open_local(
        runtime_service_group_directory_store_path(&state_dir),
    )
    .await?;
    let cleanup_workflow_store =
        WorkflowCollection::open_local(runtime_stale_participant_cleanup_store_path(&state_dir))
            .await?;
    let tombstone_history_store = ParticipantTombstoneHistoryCollection::open(
        runtime_participant_tombstone_history_store_path(&state_dir),
    )
    .await?;
    prune_runtime_participant_tombstone_history(&tombstone_history_store).await?;
    let runtime_audit_log = AuditLog::open(runtime_audit_log_path(&state_dir)).await?;
    let runtime_outbox =
        DurableEventRelay::<PlatformEvent>::open(runtime_outbox_path(&state_dir)).await?;
    let idempotency_journal =
        HttpIdempotencyJournal::open(runtime_idempotency_journal_path(&state_dir)).await?;
    let registry_reconciler = RuntimeRegistryReconciler::open_local(
        runtime_registry_reconciler_store_path(&state_dir),
        publication_plan.clone(),
        address,
    )
    .await?;
    let registration =
        activate_runtime_registration(&registration_store, &publication_plan).await?;
    let observed_at = OffsetDateTime::now_utc();
    let cell_directory = activate_runtime_cell_directory(
        &cell_directory_store,
        &registration_store,
        &cleanup_workflow_store,
        &registry_reconciler,
        &registration,
        observed_at,
    )
    .await?;
    persist_runtime_service_group_directory(&service_group_directory_store, &cell_directory)
        .await?;
    let service_group_directory = resolve_cell_service_group_directory(&cell_directory);
    let cleanup_workflows =
        list_runtime_stale_participant_cleanup_workflows(&cleanup_workflow_store).await?;
    let tombstone_history =
        list_runtime_participant_tombstone_history(&tombstone_history_store).await?;
    let topology_seed = publication_plan.publish_topology(
        &registration,
        &cell_directory,
        &service_group_directory,
        &cleanup_workflows,
        &tombstone_history,
        observed_at,
    );
    let topology_handle = RuntimeTopologyHandle::new(topology_seed);
    let readyz_handle = RuntimeReadyzHandle::default();
    let registration_context = RuntimeProcessRegistrationContext {
        store: registration_store,
        cell_directory_store,
        service_group_directory_store,
        cleanup_workflow_store,
        registry_reconciler,
        tombstone_history_store,
        audit_log: runtime_audit_log,
        outbox: runtime_outbox,
        publication_plan: publication_plan.clone(),
        topology_handle: topology_handle.clone(),
        readyz_handle: readyz_handle.clone(),
        current_fencing_token: Arc::new(Mutex::new(registration.fencing_token.clone())),
    };
    let service_factory = RuntimeServiceFactoryContext::new(
        state_dir.clone(),
        secrets_key.clone(),
        identity_service.clone(),
        registration_context.clone(),
    );
    let services = publication_plan
        .build_runtime_services(&service_factory)
        .await?;
    let mut runtime = PlatformRuntime::new_with_forwarded_services(services, forwarded_services)?
        .with_access_config(access)
        .with_idempotency_journal(idempotency_journal)
        .with_topology_handle(topology_handle)
        .with_readyz_handle(readyz_handle);
    if !forward_targets.is_empty() {
        runtime = runtime.with_route_forwarder(Arc::new(StaticServiceForwarder::new(
            forward_targets
                .iter()
                .map(|(service_name, address)| (service_name.clone(), *address)),
        )));
    }
    let renewal_task = tokio::spawn(registration_context.clone().renew_forever());
    let serve_result = runtime.serve(address).await;
    renewal_task.abort();
    let _ = renewal_task.await;
    registration_housekeeping_task.abort();
    let _ = registration_housekeeping_task.await;
    let drain_result = registration_context.request_drain().await;

    match (serve_result, drain_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
    }
}

fn parse_config_path() -> Result<PathBuf> {
    parse_config_path_from_args(env::args().skip(1))
}

fn parse_config_path_from_args<I, S>(args: I) -> Result<PathBuf>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into);
    let mut config_path = None;

    while let Some(argument) = args.next() {
        if argument == "--config" {
            let Some(path) = args.next() else {
                return Err(PlatformError::invalid("missing value after --config"));
            };
            if path.starts_with("--") {
                return Err(PlatformError::invalid(format!(
                    "missing value after --config: `{path}` looks like another flag"
                )));
            }
            if config_path.replace(PathBuf::from(path)).is_some() {
                return Err(PlatformError::invalid("duplicate --config argument"));
            }
            continue;
        }

        if let Some(path) = argument.strip_prefix("--config=") {
            if path.is_empty() {
                return Err(PlatformError::invalid("missing value after --config"));
            }
            if path.starts_with("--") {
                return Err(PlatformError::invalid(format!(
                    "missing value after --config: `{path}` looks like another flag"
                )));
            }
            if config_path.replace(PathBuf::from(path)).is_some() {
                return Err(PlatformError::invalid("duplicate --config argument"));
            }
            continue;
        }

        return Err(PlatformError::invalid("unexpected argument")
            .with_detail(format!("`{argument}` is not supported")));
    }

    Ok(config_path.unwrap_or_else(|| PathBuf::from("configs/dev/all-in-one.toml")))
}

#[cfg(test)]
mod tests {
    use super::{
        AllInOneConfig, ConfigSchema, IdentityService, PlacementConfig,
        RUNTIME_PROCESS_LEASE_DURATION_SECONDS, RUNTIME_PROCESS_SUBJECT_KIND, RuntimeConfig,
        RuntimeProcessRegistrationContext, RuntimeRegistryReconciler, RuntimeRolePublicationPlan,
        RuntimeServiceFactoryContext, SecretsConfig, SecurityConfig,
        activate_runtime_cell_directory, activate_runtime_registration,
        activation::{
            SERVICE_ROUTE_SURFACE_MANIFESTS, parse_runtime_process_role,
            route_surfaces_for_service, runtime_registration_key, runtime_role_activation_plan,
            supported_runtime_process_roles,
        },
        mutate_runtime_registration, parse_config_path_from_args,
        persist_runtime_service_group_directory, runtime_audit_log_path,
        runtime_cell_directory_store_path, runtime_outbox_path,
        runtime_participant_tombstone_history_store_path,
        runtime_process_role_requires_non_local_manifests, runtime_registration_store_path,
        runtime_registry_reconciler_store_path, runtime_role_publication_plan,
        runtime_service_group_directory_store_path, runtime_stale_participant_cleanup_store_path,
        runtime_topology, stale_participant_cleanup_next_attempt_at,
        stale_participant_cleanup_retry_interval, stale_participant_cleanup_runner_lease_duration,
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        net::SocketAddr,
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };
    use uhost_core::{ErrorCode, LoadableConfig, SecretBytes, SecretString, base64url_encode};
    use uhost_runtime::{
        RouteSurfaceBinding, RuntimeDrainIntent, RuntimeLeaseFreshness, RuntimeLogicalServiceGroup,
        RuntimeParticipantCleanupStage, RuntimeParticipantDrainPhase, RuntimeProcessRole,
        RuntimeReadinessState, RuntimeReadyzFailureReason, RuntimeReadyzHandle,
        RuntimeTopologyHandle,
    };
    use uhost_store::{
        AuditLog, CellDirectoryCollection, CellDirectoryRecord, CellParticipantDrainPhase,
        CellParticipantLeaseSource, CellParticipantLeaseState, CellParticipantReconciliationState,
        CellParticipantRecord, CellParticipantState, CellServiceGroupConflictState,
        CellServiceGroupDirectoryCollection, DurableEventRelay, LeaseDrainIntent, LeaseFreshness,
        LeaseReadiness, LeaseRegistrationCollection, LeaseRegistrationRecord,
        LocalCellRegistryState, MetadataCollection, ParticipantTombstoneHistoryCollection,
        ServiceEndpointCollection, ServiceEndpointProtocol, ServiceInstanceCollection,
        StaleParticipantCleanupStage, StaleParticipantCleanupWorkflowState, WorkflowCollection,
        WorkflowPhase, WorkflowStepState, stale_participant_cleanup_workflow,
        stale_participant_cleanup_workflow_id,
    };
    use uhost_testkit::TempState;
    use uhost_types::{PlatformEvent, ServiceMode};

    fn development_master_key() -> String {
        base64url_encode(&[0x42; 32])
    }

    fn deployment_master_key() -> String {
        base64url_encode(&[
            0x00, 0x1f, 0x82, 0x44, 0x93, 0xab, 0xcd, 0xef, 0x10, 0x22, 0x35, 0x49, 0x58, 0x6a,
            0x7c, 0x8e, 0x91, 0xa3, 0xb5, 0xc7, 0xd9, 0xeb, 0xfd, 0x0c, 0x1d, 0x2e, 0x3f, 0x40,
            0x51, 0x62, 0x73, 0x84,
        ])
    }

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("failed to derive workspace root"))
    }

    fn corrupt_collection(path: &Path) {
        let canonical = fs::canonicalize(path).unwrap_or_else(|error| {
            panic!(
                "failed to canonicalize collection path for corruption {}: {error}",
                path.display()
            )
        });
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&canonical)
            .unwrap_or_else(|error| {
                panic!(
                    "failed to open collection for corruption {}: {error}",
                    canonical.display()
                )
            });
        std::io::Write::write_all(&mut file, b"{broken-json").unwrap_or_else(|error| {
            panic!(
                "failed to corrupt collection payload {}: {error}",
                canonical.display()
            )
        });
        file.sync_all().unwrap_or_else(|error| {
            panic!(
                "failed to sync corrupted collection payload {}: {error}",
                canonical.display()
            )
        });
    }

    fn route_surface_contract_block(owner: &str, binding: RouteSurfaceBinding) -> String {
        format!(
            "  - owner: {owner}\n    claim: {}\n    match: {}\n    method_match: {}\n    surface: {}\n    request_class: {}",
            binding.path(),
            binding.match_kind(),
            binding.method_match().as_str(),
            binding.surface().as_str(),
            binding.request_class().as_str(),
        )
    }

    fn distributed_runtime_test_config_for_process_role(
        process_role: RuntimeProcessRole,
    ) -> AllInOneConfig {
        AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::Distributed,
                node_name: String::from("runtime-topology-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(deployment_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: Some(SecretString::new("0123456789abcdef0123456789abcdef")),
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig {
                process_role: Some(process_role.as_str().to_owned()),
                forward_targets: BTreeMap::new(),
            },
        }
    }

    fn publication_plan_for_test(config: &AllInOneConfig) -> RuntimeRolePublicationPlan {
        runtime_role_publication_plan(config).unwrap_or_else(|error| panic!("{error}"))
    }

    async fn runtime_registry_reconciler_for_test(
        state_dir: &Path,
        publication_plan: &RuntimeRolePublicationPlan,
    ) -> RuntimeRegistryReconciler {
        RuntimeRegistryReconciler::open_local(
            runtime_registry_reconciler_store_path(state_dir),
            publication_plan.clone(),
            SocketAddr::from(([127, 0, 0, 1], 9080)),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
    }

    async fn runtime_service_factory_context_for_test(
        state_dir: &Path,
        publication_plan: &RuntimeRolePublicationPlan,
    ) -> RuntimeServiceFactoryContext {
        let secrets_key = SecretBytes::new(vec![0x44; 32]);
        let identity_service = Arc::new(
            IdentityService::open_with_master_key(state_dir, secrets_key.clone())
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let registry_reconciler =
            runtime_registry_reconciler_for_test(state_dir, publication_plan).await;
        let registration_context = RuntimeProcessRegistrationContext {
            store: LeaseRegistrationCollection::open_local(runtime_registration_store_path(
                state_dir,
            ))
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            cell_directory_store: CellDirectoryCollection::open_local(
                runtime_cell_directory_store_path(state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            service_group_directory_store: CellServiceGroupDirectoryCollection::open_local(
                runtime_service_group_directory_store_path(state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            cleanup_workflow_store: WorkflowCollection::open_local(
                runtime_stale_participant_cleanup_store_path(state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            registry_reconciler,
            tombstone_history_store: ParticipantTombstoneHistoryCollection::open(
                runtime_participant_tombstone_history_store_path(state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            audit_log: AuditLog::open(runtime_audit_log_path(state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}")),
            outbox: DurableEventRelay::<PlatformEvent>::open(runtime_outbox_path(state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}")),
            publication_plan: publication_plan.clone(),
            topology_handle: RuntimeTopologyHandle::new(publication_plan.topology_seed()),
            readyz_handle: RuntimeReadyzHandle::default(),
            current_fencing_token: Arc::new(Mutex::new(String::new())),
        };

        RuntimeServiceFactoryContext::new(
            state_dir.to_path_buf(),
            secrets_key,
            identity_service,
            registration_context,
        )
    }

    #[test]
    fn defaults_to_dev_config_without_arguments() {
        let path = parse_config_path_from_args(std::iter::empty::<String>())
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(path, PathBuf::from("configs/dev/all-in-one.toml"));
    }

    #[test]
    fn accepts_config_flag_with_separate_value() {
        let path =
            parse_config_path_from_args(["--config".to_owned(), "/tmp/custom.toml".to_owned()])
                .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(path, PathBuf::from("/tmp/custom.toml"));
    }

    #[test]
    fn accepts_config_flag_with_equals_syntax() {
        let path = parse_config_path_from_args(["--config=/tmp/custom.toml".to_owned()])
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(path, PathBuf::from("/tmp/custom.toml"));
    }

    #[test]
    fn rejects_unknown_arguments() {
        let error = parse_config_path_from_args(["--debug".to_owned()])
            .expect_err("unexpected argument should be rejected");
        assert!(
            error.to_string().contains("unexpected argument"),
            "error should explain that unknown flags are rejected"
        );
    }

    #[test]
    fn rejects_duplicate_config_flags() {
        let error = parse_config_path_from_args([
            "--config".to_owned(),
            "/tmp/first.toml".to_owned(),
            "--config=/tmp/second.toml".to_owned(),
        ])
        .expect_err("duplicate config flags should be rejected");
        assert!(
            error.to_string().contains("duplicate --config"),
            "error should explain that duplicate config flags are rejected"
        );
    }

    #[test]
    fn rejects_missing_config_value() {
        let error = parse_config_path_from_args(["--config".to_owned()])
            .expect_err("missing config value should be rejected");
        assert!(
            error.to_string().contains("missing value after --config"),
            "error should explain that the config path is missing"
        );
    }

    #[test]
    fn rejects_empty_config_value_in_equals_syntax() {
        let error = parse_config_path_from_args(["--config=".to_owned()])
            .expect_err("empty config value should be rejected");
        assert!(
            error.to_string().contains("missing value after --config"),
            "error should explain that the config path is missing"
        );
    }

    #[test]
    fn rejects_flag_like_config_values() {
        let error = parse_config_path_from_args(["--config".to_owned(), "--debug".to_owned()])
            .expect_err("flag-like config values should be rejected");
        assert!(
            error.to_string().contains("looks like another flag"),
            "error should explain that the config path collides with a flag"
        );
    }

    #[test]
    fn config_validation_rejects_blank_bootstrap_admin_token() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: Some(SecretString::new("   ")),
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let error = config
            .validate()
            .expect_err("blank bootstrap token should be rejected");
        assert!(
            error
                .to_string()
                .contains("bootstrap_admin_token may not be empty"),
            "error should explain why blank bootstrap token is invalid"
        );
    }

    #[test]
    fn config_validation_allows_missing_bootstrap_admin_token() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        config
            .validate()
            .unwrap_or_else(|error| panic!("missing token should be allowed: {error}"));
    }

    #[test]
    fn config_validation_rejects_placeholder_bootstrap_admin_token() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::Distributed,
                node_name: String::from("test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(deployment_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: Some(SecretString::new("prod-bootstrap-change-me")),
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let error = config
            .validate()
            .expect_err("placeholder token should be rejected");
        assert!(
            error
                .to_string()
                .contains("placeholder value is not allowed"),
            "error should explain placeholder rejection"
        );
    }

    #[test]
    fn config_validation_allows_placeholder_token_in_all_in_one_mode() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: Some(SecretString::new(
                    "dev-bootstrap-admin-token-change-me",
                )),
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        config.validate().unwrap_or_else(|error| {
            panic!("all_in_one placeholder token should be allowed: {error}")
        });
    }

    #[test]
    fn config_validation_rejects_missing_bootstrap_token_outside_all_in_one_mode() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::SingleNode,
                node_name: String::from("test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(deployment_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let error = config
            .validate()
            .expect_err("single_node mode should require bootstrap token");
        assert!(
            error
                .to_string()
                .contains("bootstrap_admin_token is required"),
            "error should explain missing token requirement"
        );
    }

    #[test]
    fn config_validation_rejects_missing_master_key() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig { master_key: None },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let error = config
            .validate()
            .expect_err("missing master key should be rejected");
        assert!(
            error.to_string().contains("secrets.master_key is required"),
            "error should explain missing master key requirement"
        );
    }

    #[test]
    fn config_validation_rejects_human_readable_master_key_in_production_posture() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("test-node"),
            },
            listen: String::from("0.0.0.0:9443"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(base64url_encode(b"prod-master-key-material-32bytes")),
            },
            security: SecurityConfig {
                bootstrap_admin_token: Some(SecretString::new("0123456789abcdef0123456789abcdef")),
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let error = config
            .validate()
            .expect_err("human-readable production master key should be rejected");
        assert!(
            error
                .to_string()
                .contains("unique deployment-specific key material"),
            "error should explain that production secrets must be deployment-specific"
        );
    }

    #[test]
    fn config_validation_rejects_short_bootstrap_token_in_production_posture() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("test-node"),
            },
            listen: String::from("0.0.0.0:9443"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(deployment_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: Some(SecretString::new("short-bootstrap-token")),
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let error = config
            .validate()
            .expect_err("short bootstrap token should be rejected in production posture");
        assert!(
            error.to_string().contains("must be at least 32 characters"),
            "error should explain bootstrap token length requirements"
        );
    }

    #[test]
    fn config_validation_rejects_missing_bootstrap_token_for_public_all_in_one_listener() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("test-node"),
            },
            listen: String::from("0.0.0.0:9443"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(deployment_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let error = config
            .validate()
            .expect_err("public all_in_one listener should require bootstrap token");
        assert!(
            error
                .to_string()
                .contains("bootstrap_admin_token is required"),
            "error should explain bootstrap token requirement for public listeners"
        );
    }

    #[test]
    fn config_validation_allows_public_all_in_one_listener_with_operator_managed_secrets() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("test-node"),
            },
            listen: String::from("0.0.0.0:9443"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(deployment_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: Some(SecretString::new("0123456789abcdef0123456789abcdef")),
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        config.validate().unwrap_or_else(|error| {
            panic!("public all_in_one listener should accept operator-managed secrets: {error}")
        });
    }

    #[test]
    fn config_validation_rejects_non_all_in_one_process_role_in_all_in_one_mode() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(deployment_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig {
                process_role: Some(String::from("controller")),
                forward_targets: BTreeMap::new(),
            },
        };

        let error = config
            .validate()
            .expect_err("controller role should be rejected in all_in_one mode");
        assert!(
            error
                .to_string()
                .contains("runtime.process_role may only be non-all_in_one"),
            "error should explain non-all_in_one role placement requirements"
        );
    }

    #[test]
    fn runtime_process_role_defaults_to_all_in_one_when_omitted() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::Distributed,
                node_name: String::from("test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(deployment_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: Some(SecretString::new("0123456789abcdef0123456789abcdef")),
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        assert_eq!(
            config
                .runtime_process_role()
                .unwrap_or_else(|error| panic!("{error}")),
            RuntimeProcessRole::AllInOne
        );
    }

    #[test]
    fn runtime_role_publication_plan_defaults_to_all_in_one_when_omitted() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::Distributed,
                node_name: String::from("test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(deployment_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: Some(SecretString::new("0123456789abcdef0123456789abcdef")),
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let publication_plan =
            runtime_role_publication_plan(&config).unwrap_or_else(|error| panic!("{error}"));
        let topology = publication_plan.topology_seed();

        assert_eq!(
            publication_plan.process_role(),
            RuntimeProcessRole::AllInOne
        );
        assert_eq!(publication_plan.registration_key(), "all_in_one:test-node");
        assert_eq!(publication_plan.node_name(), "test-node");
        assert_eq!(topology.process_role, RuntimeProcessRole::AllInOne);
        assert_eq!(topology.node_name.as_deref(), Some("test-node"));
    }

    #[test]
    fn config_validation_accepts_supported_runtime_process_roles_from_activation_catalog() {
        for process_role in supported_runtime_process_roles() {
            let mut config = distributed_runtime_test_config_for_process_role(process_role);
            if runtime_process_role_requires_non_local_manifests(process_role) {
                config
                    .runtime
                    .forward_targets
                    .insert(String::from("policy"), String::from("127.0.0.1:9444"));
            }

            config.validate().unwrap_or_else(|error| {
                panic!(
                    "{} role should be accepted in distributed mode: {error}",
                    process_role.as_str()
                )
            });
            assert_eq!(
                parse_runtime_process_role(process_role.as_str()),
                Some(process_role),
                "runtime role parser rejected supported role `{}`",
                process_role.as_str()
            );
            assert_eq!(
                parse_runtime_process_role(&format!(" {} ", process_role.as_str())),
                Some(process_role),
                "runtime role parser failed to trim supported role `{}`",
                process_role.as_str()
            );
        }

        assert_eq!(parse_runtime_process_role("unsupported"), None);
    }

    #[test]
    fn runtime_process_role_validation_error_lists_supported_roles_from_activation_catalog() {
        let mut config = distributed_runtime_test_config_for_process_role(RuntimeProcessRole::Edge);
        config.runtime.process_role = Some(String::from("unsupported"));

        let error = config
            .runtime_process_role()
            .expect_err("unsupported runtime role should be rejected");
        let supported_roles = supported_runtime_process_roles()
            .map(RuntimeProcessRole::as_str)
            .collect::<Vec<_>>()
            .join(", ");

        assert!(
            error
                .to_string()
                .contains(&format!("expected one of {supported_roles}")),
            "error should list activation-catalog runtime roles"
        );
    }

    #[test]
    fn config_validation_accepts_non_local_forward_targets() {
        let mut config = distributed_runtime_test_config_for_process_role(RuntimeProcessRole::Edge);
        config
            .runtime
            .forward_targets
            .insert(String::from("identity"), String::from("127.0.0.1:9444"));

        config
            .validate()
            .unwrap_or_else(|error| panic!("non-local forward target should validate: {error}"));

        let publication_plan = publication_plan_for_test(&config);
        let targets = config
            .runtime_forward_targets(
                &publication_plan,
                &"127.0.0.1:9080"
                    .parse()
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            targets.get("identity"),
            Some(
                &"127.0.0.1:9444"
                    .parse()
                    .unwrap_or_else(|error| panic!("{error}"))
            )
        );
    }

    #[test]
    fn config_validation_accepts_shared_group_non_local_forward_targets() {
        let mut config =
            distributed_runtime_test_config_for_process_role(RuntimeProcessRole::NodeAdjacent);
        config
            .runtime
            .forward_targets
            .insert(String::from("control"), String::from("127.0.0.1:9444"));
        config
            .runtime
            .forward_targets
            .insert(String::from("uvm-control"), String::from("127.0.0.1:9445"));

        config.validate().unwrap_or_else(|error| {
            panic!(
                "shared-group non-local forward targets should validate for node-adjacent: {error}"
            )
        });

        let publication_plan = publication_plan_for_test(&config);
        let targets = config
            .runtime_forward_targets(
                &publication_plan,
                &"127.0.0.1:9080"
                    .parse()
                    .unwrap_or_else(|error| panic!("{error}")),
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            targets.get("control"),
            Some(
                &"127.0.0.1:9444"
                    .parse()
                    .unwrap_or_else(|error| panic!("{error}"))
            )
        );
        assert_eq!(
            targets.get("uvm-control"),
            Some(
                &"127.0.0.1:9445"
                    .parse()
                    .unwrap_or_else(|error| panic!("{error}"))
            )
        );
    }

    #[test]
    fn config_validation_rejects_split_roles_with_only_local_manifests() {
        for process_role in [
            RuntimeProcessRole::Edge,
            RuntimeProcessRole::Worker,
            RuntimeProcessRole::NodeAdjacent,
        ] {
            let config = distributed_runtime_test_config_for_process_role(process_role);

            let error = config
                .validate()
                .expect_err("split role should require at least one non-local forward target");
            assert!(
                error.to_string().contains(&format!(
                    "runtime.process_role `{}` may not activate with only local manifests",
                    process_role.as_str()
                )),
                "unexpected error for role `{}`: {error}",
                process_role.as_str()
            );
        }
    }

    #[test]
    fn config_validation_rejects_local_forward_targets() {
        let mut config = distributed_runtime_test_config_for_process_role(RuntimeProcessRole::Edge);
        config
            .runtime
            .forward_targets
            .insert(String::from("ingress"), String::from("127.0.0.1:9444"));

        let error = config
            .validate()
            .expect_err("locally activated forward target should be rejected");
        assert!(
            error
                .to_string()
                .contains("may not target locally activated service `ingress`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn runtime_service_group_manifest_covers_every_registered_service_once() {
        let expected = SERVICE_ROUTE_SURFACE_MANIFESTS
            .iter()
            .filter(|manifest| {
                !matches!(
                    manifest.service_name(),
                    "runtime-operator" | "runtime-internal"
                )
            })
            .map(|manifest| manifest.service_name())
            .collect::<BTreeSet<_>>();
        let activation_plan = runtime_role_activation_plan(RuntimeProcessRole::AllInOne);
        let mut observed = BTreeSet::new();

        for manifest in activation_plan.service_groups() {
            assert!(
                manifest.service_names().next().is_some(),
                "runtime topology group {:?} must not be empty",
                manifest.group
            );
            for service_name in manifest.service_names() {
                assert!(
                    observed.insert(service_name),
                    "service `{service_name}` appears in multiple runtime topology groups"
                );
                route_surfaces_for_service(service_name).unwrap_or_else(|error| {
                    panic!("missing route manifest for {service_name}: {error}")
                });
            }
        }

        assert_eq!(observed, expected);
    }

    #[test]
    fn runtime_role_activation_plan_derives_forwardable_non_local_services_from_manifests() {
        let expectations: &[(RuntimeProcessRole, &[&str])] = &[
            (RuntimeProcessRole::AllInOne, &[]),
            (
                RuntimeProcessRole::Edge,
                &[
                    "abuse",
                    "billing",
                    "container",
                    "control",
                    "data",
                    "governance",
                    "ha",
                    "identity",
                    "lifecycle",
                    "mail",
                    "netsec",
                    "node",
                    "notify",
                    "observe",
                    "policy",
                    "scheduler",
                    "secrets",
                    "storage",
                    "stream",
                    "tenancy",
                    "uvm-control",
                    "uvm-image",
                    "uvm-node",
                    "uvm-observe",
                ],
            ),
            (
                RuntimeProcessRole::Controller,
                &[
                    "console", "data", "dns", "ingress", "mail", "netsec", "storage", "stream",
                ],
            ),
            (
                RuntimeProcessRole::Worker,
                &[
                    "abuse",
                    "billing",
                    "console",
                    "container",
                    "control",
                    "dns",
                    "governance",
                    "ha",
                    "identity",
                    "ingress",
                    "lifecycle",
                    "node",
                    "notify",
                    "observe",
                    "policy",
                    "scheduler",
                    "secrets",
                    "tenancy",
                    "uvm-control",
                    "uvm-image",
                    "uvm-node",
                    "uvm-observe",
                ],
            ),
            (
                RuntimeProcessRole::NodeAdjacent,
                &[
                    "abuse",
                    "billing",
                    "console",
                    "container",
                    "control",
                    "data",
                    "dns",
                    "governance",
                    "ha",
                    "identity",
                    "ingress",
                    "lifecycle",
                    "mail",
                    "netsec",
                    "notify",
                    "observe",
                    "policy",
                    "scheduler",
                    "secrets",
                    "storage",
                    "stream",
                    "tenancy",
                    "uvm-control",
                    "uvm-image",
                    "uvm-observe",
                ],
            ),
        ];

        for (process_role, expected_service_names) in expectations {
            let activation_plan = runtime_role_activation_plan(*process_role);
            assert_eq!(
                activation_plan.forwardable_non_local_service_names(),
                expected_service_names.to_vec(),
                "unexpected forwardable non-local services for role `{}`",
                process_role.as_str()
            );
        }
    }

    #[test]
    fn runtime_role_activation_plan_activates_only_intended_services_for_supported_roles() {
        let expectations: &[(RuntimeProcessRole, &[&str])] = &[
            (
                RuntimeProcessRole::AllInOne,
                &[
                    "abuse",
                    "billing",
                    "console",
                    "container",
                    "control",
                    "data",
                    "dns",
                    "governance",
                    "ha",
                    "identity",
                    "ingress",
                    "lifecycle",
                    "mail",
                    "netsec",
                    "node",
                    "notify",
                    "observe",
                    "policy",
                    "scheduler",
                    "secrets",
                    "storage",
                    "stream",
                    "tenancy",
                    "uvm-control",
                    "uvm-image",
                    "uvm-node",
                    "uvm-observe",
                ],
            ),
            (RuntimeProcessRole::Edge, &["console", "dns", "ingress"]),
            (
                RuntimeProcessRole::Controller,
                &[
                    "abuse",
                    "billing",
                    "container",
                    "control",
                    "governance",
                    "ha",
                    "identity",
                    "lifecycle",
                    "node",
                    "notify",
                    "observe",
                    "policy",
                    "scheduler",
                    "secrets",
                    "tenancy",
                    "uvm-control",
                    "uvm-image",
                    "uvm-node",
                    "uvm-observe",
                ],
            ),
            (
                RuntimeProcessRole::Worker,
                &["data", "mail", "netsec", "storage", "stream"],
            ),
            (RuntimeProcessRole::NodeAdjacent, &["node", "uvm-node"]),
        ];

        let expected_roles = supported_runtime_process_roles()
            .map(RuntimeProcessRole::as_str)
            .collect::<BTreeSet<_>>();
        let observed_roles = expectations
            .iter()
            .map(|(process_role, _)| process_role.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            observed_roles, expected_roles,
            "activation-plan expectations should cover every supported runtime role"
        );

        for (process_role, expected_services) in expectations {
            let activation_plan = runtime_role_activation_plan(*process_role);
            assert_eq!(
                activation_plan.activated_service_names(),
                expected_services.to_vec(),
                "unexpected activated services for role `{}`",
                process_role.as_str()
            );
        }
    }

    #[tokio::test]
    async fn runtime_service_factory_builds_only_role_expected_service_instances() {
        for process_role in supported_runtime_process_roles() {
            let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
            let state_dir = state
                .create_dir_all("state")
                .unwrap_or_else(|error| panic!("{error}"));
            let config = distributed_runtime_test_config_for_process_role(process_role);
            let publication_plan = publication_plan_for_test(&config);
            let context =
                runtime_service_factory_context_for_test(&state_dir, &publication_plan).await;
            let activation_plan = runtime_role_activation_plan(process_role);
            let actual_service_names = publication_plan
                .build_runtime_service_names(&context)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let mut expected_service_names = activation_plan.activated_service_names();
            expected_service_names.push("runtime-operator");
            expected_service_names.push("runtime-internal");
            expected_service_names.sort_unstable();
            expected_service_names.dedup();

            assert_eq!(
                actual_service_names,
                expected_service_names,
                "unexpected concrete service activation for role `{}`",
                process_role.as_str()
            );
        }
    }

    #[tokio::test]
    async fn runtime_topology_stays_truthful_to_actual_service_activation_for_supported_roles() {
        for process_role in supported_runtime_process_roles() {
            let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
            let state_dir = state
                .create_dir_all("state")
                .unwrap_or_else(|error| panic!("{error}"));
            let config = distributed_runtime_test_config_for_process_role(process_role);
            let publication_plan = publication_plan_for_test(&config);
            let context =
                runtime_service_factory_context_for_test(&state_dir, &publication_plan).await;
            let mut actual_service_names = publication_plan
                .build_runtime_service_names(&context)
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .into_iter()
                .filter(|service_name| {
                    !matches!(*service_name, "runtime-operator" | "runtime-internal")
                })
                .map(str::to_owned)
                .collect::<Vec<_>>();
            actual_service_names.sort_unstable();
            actual_service_names.dedup();

            let topology = publication_plan.topology_seed();
            let mut topology_service_names = topology
                .service_groups
                .iter()
                .flat_map(|ownership| ownership.services.iter().cloned())
                .collect::<Vec<_>>();
            topology_service_names.sort_unstable();
            topology_service_names.dedup();

            assert_eq!(
                topology_service_names,
                actual_service_names,
                "runtime topology reported unexpected activated services for role `{}`",
                process_role.as_str()
            );
            assert!(
                topology
                    .service_groups
                    .iter()
                    .all(|ownership| ownership.owner_role == process_role),
                "runtime topology reported an unexpected owner role for `{}`",
                process_role.as_str()
            );
        }
    }

    #[test]
    fn runtime_topology_stays_truthful_to_role_activation_plan_for_supported_roles() {
        for process_role in supported_runtime_process_roles() {
            let config = distributed_runtime_test_config_for_process_role(process_role);
            let publication_plan = publication_plan_for_test(&config);
            let topology = publication_plan.topology_seed();
            let activation_plan = runtime_role_activation_plan(process_role);

            assert_eq!(topology.process_role, process_role);
            assert_eq!(
                topology.service_groups.len(),
                activation_plan.service_groups().len(),
                "unexpected topology group count for role `{}`",
                process_role.as_str()
            );

            for manifest in activation_plan.service_groups() {
                let ownership = topology
                    .service_groups
                    .iter()
                    .find(|ownership| ownership.group == manifest.group)
                    .unwrap_or_else(|| {
                        panic!(
                            "missing topology ownership for role `{}` and group `{}`",
                            process_role.as_str(),
                            manifest.group.as_str()
                        )
                    });
                assert_eq!(ownership.owner_role, process_role);
                assert_eq!(ownership.services, manifest.sorted_service_names());
            }
        }
    }

    #[test]
    fn runtime_cell_participant_reports_service_groups_from_role_activation_plan() {
        let observed_at = time::OffsetDateTime::now_utc();

        for process_role in supported_runtime_process_roles() {
            let mut config = distributed_runtime_test_config_for_process_role(process_role);
            config.schema.node_name = String::from("activation-plan-test-node");
            let publication_plan = publication_plan_for_test(&config);
            let registration = LeaseRegistrationRecord::new(
                publication_plan.registration_key(),
                RUNTIME_PROCESS_SUBJECT_KIND,
                publication_plan.registration_key(),
                publication_plan.process_role().as_str(),
                Some(publication_plan.node_name().to_owned()),
                RUNTIME_PROCESS_LEASE_DURATION_SECONDS,
            )
            .with_readiness(LeaseReadiness::Ready);
            let participant = publication_plan.cell_participant(&registration, observed_at);
            let mut expected_service_groups = publication_plan
                .topology_seed()
                .service_groups
                .iter()
                .map(|ownership| ownership.group.as_str().to_owned())
                .collect::<Vec<_>>();
            expected_service_groups.sort_unstable();

            assert_eq!(
                participant.registration_id,
                publication_plan.registration_key()
            );
            assert_eq!(participant.role, process_role.as_str());
            assert_eq!(participant.service_groups, expected_service_groups);
        }
    }

    #[test]
    fn runtime_topology_uses_explicit_all_in_one_process_role() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::Distributed,
                node_name: String::from("runtime-topology-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: Some(SecretString::new("0123456789abcdef0123456789abcdef")),
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let topology = runtime_topology(&config).unwrap_or_else(|error| panic!("{error}"));
        let edge = topology
            .service_groups
            .iter()
            .find(|group| group.group == RuntimeLogicalServiceGroup::Edge)
            .unwrap_or_else(|| panic!("missing edge topology group"));

        assert_eq!(topology.process_role, RuntimeProcessRole::AllInOne);
        assert_eq!(topology.deployment_mode, ServiceMode::Distributed);
        assert_eq!(
            topology.node_name.as_deref(),
            Some("runtime-topology-test-node")
        );
        assert_eq!(topology.region.region_id, "local");
        assert_eq!(topology.region.region_name, "local");
        assert_eq!(topology.cell.cell_id, "local:local-cell");
        assert_eq!(topology.cell.cell_name, "local-cell");
        assert!(topology.participants.is_empty());
        assert_eq!(edge.owner_role, RuntimeProcessRole::AllInOne);
        assert_eq!(edge.services, vec!["console", "dns", "ingress"]);
    }

    #[test]
    fn runtime_topology_can_report_edge_owned_service_groups() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::Distributed,
                node_name: String::from("runtime-topology-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: Some(SecretString::new("0123456789abcdef0123456789abcdef")),
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig {
                process_role: Some(String::from("edge")),
                forward_targets: BTreeMap::new(),
            },
        };

        let topology = runtime_topology(&config).unwrap_or_else(|error| panic!("{error}"));
        let groups = topology
            .service_groups
            .iter()
            .map(|group| group.group.as_str())
            .collect::<BTreeSet<_>>();
        let expected_groups = ["edge"].into_iter().collect::<BTreeSet<_>>();
        let edge = topology
            .service_groups
            .iter()
            .find(|group| group.group == RuntimeLogicalServiceGroup::Edge)
            .unwrap_or_else(|| panic!("missing edge topology group"));

        assert_eq!(topology.process_role, RuntimeProcessRole::Edge);
        assert_eq!(topology.deployment_mode, ServiceMode::Distributed);
        assert_eq!(groups, expected_groups);
        assert!(topology.participants.is_empty());
        assert!(
            topology
                .service_groups
                .iter()
                .all(|group| group.owner_role == RuntimeProcessRole::Edge)
        );
        assert_eq!(edge.services, vec!["console", "dns", "ingress"]);
    }

    #[test]
    fn runtime_topology_can_report_controller_owned_service_groups() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::Distributed,
                node_name: String::from("runtime-topology-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: Some(SecretString::new("0123456789abcdef0123456789abcdef")),
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig {
                process_role: Some(String::from("controller")),
                forward_targets: BTreeMap::new(),
            },
        };

        let topology = runtime_topology(&config).unwrap_or_else(|error| panic!("{error}"));
        let groups = topology
            .service_groups
            .iter()
            .map(|group| group.group.as_str())
            .collect::<BTreeSet<_>>();
        let expected_groups = [
            "control",
            "governance_and_operations",
            "identity_and_policy",
            "uvm",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let identity_and_policy = topology
            .service_groups
            .iter()
            .find(|group| group.group == RuntimeLogicalServiceGroup::IdentityAndPolicy)
            .unwrap_or_else(|| panic!("missing identity-and-policy topology group"));
        let control = topology
            .service_groups
            .iter()
            .find(|group| group.group == RuntimeLogicalServiceGroup::Control)
            .unwrap_or_else(|| panic!("missing control topology group"));

        assert_eq!(topology.process_role, RuntimeProcessRole::Controller);
        assert_eq!(topology.deployment_mode, ServiceMode::Distributed);
        assert_eq!(groups, expected_groups);
        assert!(
            topology
                .service_groups
                .iter()
                .all(|group| group.owner_role == RuntimeProcessRole::Controller)
        );
        assert_eq!(
            identity_and_policy.services,
            vec!["identity", "policy", "secrets", "tenancy"]
        );
        assert_eq!(
            control.services,
            vec![
                "container",
                "control",
                "ha",
                "lifecycle",
                "node",
                "scheduler"
            ]
        );
    }

    #[test]
    fn runtime_topology_can_report_worker_owned_service_groups() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::Distributed,
                node_name: String::from("runtime-topology-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: Some(SecretString::new("0123456789abcdef0123456789abcdef")),
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig {
                process_role: Some(String::from("worker")),
                forward_targets: BTreeMap::new(),
            },
        };

        let topology = runtime_topology(&config).unwrap_or_else(|error| panic!("{error}"));
        let groups = topology
            .service_groups
            .iter()
            .map(|group| group.group.as_str())
            .collect::<BTreeSet<_>>();
        let expected_groups = ["data_and_messaging"].into_iter().collect::<BTreeSet<_>>();
        let data_and_messaging = topology
            .service_groups
            .iter()
            .find(|group| group.group == RuntimeLogicalServiceGroup::DataAndMessaging)
            .unwrap_or_else(|| panic!("missing data-and-messaging topology group"));

        assert_eq!(topology.process_role, RuntimeProcessRole::Worker);
        assert_eq!(topology.deployment_mode, ServiceMode::Distributed);
        assert_eq!(groups, expected_groups);
        assert!(topology.participants.is_empty());
        assert!(
            topology
                .service_groups
                .iter()
                .all(|group| group.owner_role == RuntimeProcessRole::Worker)
        );
        assert_eq!(
            data_and_messaging.services,
            vec!["data", "mail", "netsec", "storage", "stream"]
        );
    }

    #[test]
    fn runtime_topology_can_report_node_adjacent_owned_service_groups() {
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::Distributed,
                node_name: String::from("runtime-topology-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: String::from("./state"),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: Some(SecretString::new("0123456789abcdef0123456789abcdef")),
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig {
                process_role: Some(String::from("node_adjacent")),
                forward_targets: BTreeMap::new(),
            },
        };

        let topology = runtime_topology(&config).unwrap_or_else(|error| panic!("{error}"));
        let groups = topology
            .service_groups
            .iter()
            .map(|group| group.group.as_str())
            .collect::<BTreeSet<_>>();
        let expected_groups = ["control", "uvm"].into_iter().collect::<BTreeSet<_>>();
        let control = topology
            .service_groups
            .iter()
            .find(|group| group.group == RuntimeLogicalServiceGroup::Control)
            .unwrap_or_else(|| panic!("missing control topology group"));
        let uvm = topology
            .service_groups
            .iter()
            .find(|group| group.group == RuntimeLogicalServiceGroup::Uvm)
            .unwrap_or_else(|| panic!("missing uvm topology group"));

        assert_eq!(topology.process_role, RuntimeProcessRole::NodeAdjacent);
        assert_eq!(topology.deployment_mode, ServiceMode::Distributed);
        assert_eq!(groups, expected_groups);
        assert!(topology.participants.is_empty());
        assert!(
            topology
                .service_groups
                .iter()
                .all(|group| group.owner_role == RuntimeProcessRole::NodeAdjacent)
        );
        assert_eq!(control.services, vec!["node"]);
        assert_eq!(uvm.services, vec!["uvm-node"]);
    }

    #[tokio::test]
    async fn runtime_cell_directory_activation_persists_default_local_membership() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let state_dir = state
            .create_dir_all("state")
            .unwrap_or_else(|error| panic!("{error}"));
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("cell-directory-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: state_dir.display().to_string(),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let publication_plan = publication_plan_for_test(&config);
        let directory_a =
            CellDirectoryCollection::open_local(runtime_cell_directory_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let directory_b =
            CellDirectoryCollection::open_local(runtime_cell_directory_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let service_instance_store =
            ServiceInstanceCollection::open(super::runtime_service_instance_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let service_endpoint_store =
            ServiceEndpointCollection::open(super::runtime_service_endpoint_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let service_group_directory_store = CellServiceGroupDirectoryCollection::open_local(
            runtime_service_group_directory_store_path(&state_dir),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let cleanup_workflow_store =
            WorkflowCollection::<StaleParticipantCleanupWorkflowState>::open_local(
                runtime_stale_participant_cleanup_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let placement = config
            .runtime_cell_placement()
            .unwrap_or_else(|error| panic!("{error}"));
        let registration_key = publication_plan.registration_key().to_owned();
        let registration_store =
            LeaseRegistrationCollection::open_local(runtime_registration_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let registry_reconciler =
            runtime_registry_reconciler_for_test(&state_dir, &publication_plan).await;
        let registration = activate_runtime_registration(&registration_store, &publication_plan)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let observed_at = time::OffsetDateTime::now_utc();

        let directory = activate_runtime_cell_directory(
            &directory_a,
            &registration_store,
            &cleanup_workflow_store,
            &registry_reconciler,
            &registration,
            observed_at,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        persist_runtime_service_group_directory(&service_group_directory_store, &directory)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(directory.cell_id, "local:local-cell");
        assert_eq!(directory.cell_name, "local-cell");
        assert_eq!(directory.region.region_id, "local");
        assert_eq!(directory.region.region_name, "local");

        let stored = directory_b
            .get(placement.cell_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing durable cell directory"));
        let participant = stored
            .value
            .participants
            .first()
            .unwrap_or_else(|| panic!("missing durable participant registration"));
        assert_eq!(stored.value.cell_id, "local:local-cell");
        assert_eq!(stored.value.cell_name, "local-cell");
        assert_eq!(stored.value.region.region_id, "local");
        assert_eq!(stored.value.region.region_name, "local");
        assert_eq!(participant.registration_id, registration_key);
        assert_eq!(participant.participant_kind, RUNTIME_PROCESS_SUBJECT_KIND);
        assert_eq!(participant.subject_id, registration_key);
        assert_eq!(participant.role, RuntimeProcessRole::AllInOne.as_str());
        assert_eq!(
            participant.node_name.as_deref(),
            Some("cell-directory-test-node")
        );
        assert_eq!(
            participant.lease_registration_id.as_deref(),
            Some(registration_key.as_str())
        );
        let participant_state = participant
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing participant state"));
        assert_eq!(participant_state.readiness, LeaseReadiness::Ready);
        assert_eq!(participant_state.drain_intent, LeaseDrainIntent::Serving);
        assert_eq!(
            participant_state.lease.duration_seconds,
            RUNTIME_PROCESS_LEASE_DURATION_SECONDS
        );
        assert_eq!(participant_state.lease.freshness, LeaseFreshness::Fresh);
        let reconciliation = participant
            .reconciliation
            .as_ref()
            .unwrap_or_else(|| panic!("missing participant reconciliation metadata"));
        assert!(reconciliation.stale_since.is_none());
        assert!(reconciliation.cleanup_workflow_id.is_none());
        assert_eq!(
            participant.service_groups,
            vec![
                String::from("control"),
                String::from("data_and_messaging"),
                String::from("edge"),
                String::from("governance_and_operations"),
                String::from("identity_and_policy"),
                String::from("uvm"),
            ]
        );
        let cleanup_workflows = cleanup_workflow_store
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(cleanup_workflows.is_empty());
        let stored_service_group_directory = service_group_directory_store
            .get(placement.cell_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing durable service-group directory"));
        let edge = stored_service_group_directory
            .value
            .groups
            .iter()
            .find(|entry| entry.group == "edge")
            .unwrap_or_else(|| panic!("missing edge service-group directory entry"));
        assert_eq!(
            edge.resolved_registration_ids,
            vec![registration_key.clone()]
        );
        assert_eq!(
            edge.conflict_state,
            CellServiceGroupConflictState::NoConflict
        );
        assert_eq!(edge.registrations.len(), 1);
        assert!(edge.registrations[0].healthy);
        assert_eq!(
            edge.registrations[0].lease_freshness,
            Some(LeaseFreshness::Fresh)
        );

        let mut active_service_instance_ids = service_instance_store
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter_map(|(key, stored)| (!stored.deleted).then_some(key))
            .collect::<Vec<_>>();
        active_service_instance_ids.sort_unstable();
        assert_eq!(
            active_service_instance_ids,
            vec![
                String::from("control:all_in_one:cell-directory-test-node"),
                String::from("data_and_messaging:all_in_one:cell-directory-test-node"),
                String::from("edge:all_in_one:cell-directory-test-node"),
                String::from("governance_and_operations:all_in_one:cell-directory-test-node"),
                String::from("identity_and_policy:all_in_one:cell-directory-test-node"),
                String::from("uvm:all_in_one:cell-directory-test-node"),
            ]
        );
        let control_instance = service_instance_store
            .get("control:all_in_one:cell-directory-test-node")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing control service instance"));
        assert!(!control_instance.deleted);
        assert_eq!(control_instance.value.cell_id, "local:local-cell");
        assert_eq!(control_instance.value.service_group, "control");
        assert_eq!(
            control_instance.value.participant_registration_id,
            registration_key
        );
        assert_eq!(
            control_instance.value.readiness,
            Some(LeaseReadiness::Ready)
        );
        assert_eq!(
            control_instance.value.drain_intent,
            Some(LeaseDrainIntent::Serving)
        );
        assert_eq!(
            control_instance.value.linked_lease_ids,
            vec![String::from("all_in_one:cell-directory-test-node")]
        );
        assert_eq!(control_instance.value.revision, stored.version);
        let mut active_service_endpoint_ids = service_endpoint_store
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter_map(|(key, stored)| (!stored.deleted).then_some(key))
            .collect::<Vec<_>>();
        active_service_endpoint_ids.sort_unstable();
        assert_eq!(
            active_service_endpoint_ids,
            vec![
                String::from("control:all_in_one:cell-directory-test-node:http:127.0.0.1:9080"),
                String::from(
                    "data_and_messaging:all_in_one:cell-directory-test-node:http:127.0.0.1:9080"
                ),
                String::from("edge:all_in_one:cell-directory-test-node:http:127.0.0.1:9080"),
                String::from(
                    "governance_and_operations:all_in_one:cell-directory-test-node:http:127.0.0.1:9080"
                ),
                String::from(
                    "identity_and_policy:all_in_one:cell-directory-test-node:http:127.0.0.1:9080"
                ),
                String::from("uvm:all_in_one:cell-directory-test-node:http:127.0.0.1:9080"),
            ]
        );
        let control_endpoint = service_endpoint_store
            .get("control:all_in_one:cell-directory-test-node:http:127.0.0.1:9080")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing control service endpoint"));
        assert!(!control_endpoint.deleted);
        assert_eq!(control_endpoint.value.address, "127.0.0.1:9080");
        assert_eq!(
            control_endpoint.value.protocol,
            ServiceEndpointProtocol::Http
        );
        assert_eq!(control_endpoint.value.service_group, "control");
        assert_eq!(
            control_endpoint.value.participant_registration_id,
            registration_key
        );
        assert_eq!(
            control_endpoint.value.readiness,
            Some(LeaseReadiness::Ready)
        );
        assert_eq!(
            control_endpoint.value.drain_intent,
            Some(LeaseDrainIntent::Serving)
        );
        assert_eq!(control_endpoint.value.revision, stored.version);
        assert_eq!(
            control_endpoint.value.linked_lease_ids,
            vec![String::from("all_in_one:cell-directory-test-node")]
        );
    }

    #[tokio::test]
    async fn runtime_cell_directory_activation_advances_cleanup_workflow_for_repeatedly_stale_peer()
    {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let state_dir = state
            .create_dir_all("state")
            .unwrap_or_else(|error| panic!("{error}"));
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("anti-entropy-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: state_dir.display().to_string(),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let publication_plan = publication_plan_for_test(&config);
        let topology_seed = publication_plan.topology_seed();
        let placement = config
            .runtime_cell_placement()
            .unwrap_or_else(|error| panic!("{error}"));
        let registration_store =
            LeaseRegistrationCollection::open_local(runtime_registration_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store =
            CellDirectoryCollection::open_local(runtime_cell_directory_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cleanup_workflow_store =
            WorkflowCollection::<StaleParticipantCleanupWorkflowState>::open_local(
                runtime_stale_participant_cleanup_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let tombstone_history_store = ParticipantTombstoneHistoryCollection::open(
            runtime_participant_tombstone_history_store_path(&state_dir),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let audit_log = AuditLog::open(runtime_audit_log_path(&state_dir))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let outbox = DurableEventRelay::<PlatformEvent>::open(runtime_outbox_path(&state_dir))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let registry_reconciler =
            runtime_registry_reconciler_for_test(&state_dir, &publication_plan).await;
        let stale_peer_key =
            runtime_registration_key(RuntimeProcessRole::Controller, "stale-peer-node");
        let stale_peer_publication_plan =
            runtime_role_activation_plan(RuntimeProcessRole::Controller).publication_plan(
                config.schema.mode,
                String::from("stale-peer-node"),
                placement.region_membership(),
                placement.cell_membership(),
            );
        let stale_peer_registration =
            activate_runtime_registration(&registration_store, &stale_peer_publication_plan)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let _stale_peer_registration = mutate_runtime_registration(
            &registration_store,
            stale_peer_key.as_str(),
            |registration| {
                registration.expire_now();
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_or_else(|| panic!("missing stale peer registration"));
        let seeded_directory = CellDirectoryRecord::new(
            placement.cell_id.clone(),
            placement.cell_name.clone(),
            placement.region_record(),
        )
        .with_participant(
            stale_peer_publication_plan
                .cell_participant(&stale_peer_registration, time::OffsetDateTime::now_utc())
                .with_reconciliation(
                    CellParticipantReconciliationState::new(
                        time::OffsetDateTime::now_utc() - time::Duration::seconds(20),
                    )
                    .with_stale_since(
                        time::OffsetDateTime::now_utc() - time::Duration::seconds(45),
                    ),
                ),
        );
        cell_directory_store
            .upsert(placement.cell_id.as_str(), seeded_directory, None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let registration_key = publication_plan.registration_key().to_owned();
        let registration = activate_runtime_registration(&registration_store, &publication_plan)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let observed_at = time::OffsetDateTime::now_utc();
        let directory = activate_runtime_cell_directory(
            &cell_directory_store,
            &registration_store,
            &cleanup_workflow_store,
            &registry_reconciler,
            &registration,
            observed_at,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(directory.participants.len(), 2);
        let healthy_participant = directory
            .participants
            .iter()
            .find(|participant| participant.registration_id == registration_key)
            .unwrap_or_else(|| panic!("missing current runtime participant"));
        let healthy_state = healthy_participant
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing current runtime participant state"));
        let healthy_reconciliation = healthy_participant
            .reconciliation
            .as_ref()
            .unwrap_or_else(|| panic!("missing current runtime participant reconciliation"));
        assert_eq!(healthy_state.readiness, LeaseReadiness::Ready);
        assert_eq!(healthy_state.drain_intent, LeaseDrainIntent::Serving);
        assert_eq!(healthy_state.lease.freshness, LeaseFreshness::Fresh);
        assert!(healthy_reconciliation.stale_since.is_none());
        assert!(healthy_reconciliation.cleanup_workflow_id.is_none());

        let stale_peer_participant = directory
            .participants
            .iter()
            .find(|participant| participant.registration_id == stale_peer_key)
            .unwrap_or_else(|| panic!("missing stale peer participant"));
        let stale_peer_state = stale_peer_participant
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing stale peer participant state"));
        let stale_peer_reconciliation = stale_peer_participant
            .reconciliation
            .as_ref()
            .unwrap_or_else(|| panic!("missing stale peer participant reconciliation"));
        assert_eq!(stale_peer_state.readiness, LeaseReadiness::Ready);
        assert_eq!(stale_peer_state.drain_intent, LeaseDrainIntent::Draining);
        assert_eq!(stale_peer_state.lease.freshness, LeaseFreshness::Expired);
        assert!(stale_peer_reconciliation.stale_since.is_some());
        let cleanup_workflow_id = stale_participant_cleanup_workflow_id(
            placement.cell_id.clone(),
            stale_peer_key.clone(),
        );
        assert_eq!(
            stale_peer_reconciliation.cleanup_workflow_id.as_deref(),
            Some(cleanup_workflow_id.as_str())
        );

        let pending_workflow = cleanup_workflow_store
            .get(cleanup_workflow_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stale peer cleanup workflow"));
        assert_eq!(
            pending_workflow.value.workflow_kind,
            "runtime.participant.cleanup.v1"
        );
        assert!(!pending_workflow.deleted);
        assert_eq!(pending_workflow.value.phase, WorkflowPhase::Pending);
        assert_eq!(pending_workflow.value.current_step_index, None);
        assert_eq!(pending_workflow.value.subject_kind, "cell_participant");
        assert_eq!(pending_workflow.value.subject_id, stale_peer_key);
        assert_eq!(pending_workflow.value.state.cell_id, placement.cell_id);
        assert_eq!(
            pending_workflow.value.state.participant_registration_id,
            "controller:stale-peer-node"
        );
        assert_eq!(pending_workflow.value.state.participant_role, "controller");
        assert_eq!(
            pending_workflow.value.state.stage,
            StaleParticipantCleanupStage::PendingReview
        );
        assert_eq!(pending_workflow.value.state.review_observations, 1);
        assert!(
            pending_workflow
                .value
                .state
                .preflight_confirmed_at
                .is_none()
        );
        assert!(pending_workflow.value.state.route_withdrawal.is_none());
        assert!(pending_workflow.value.state.target_readiness.is_none());
        assert!(pending_workflow.value.state.rollback.is_none());
        assert!(pending_workflow.value.state.tombstone_eligible_at.is_none());
        assert_eq!(
            pending_workflow.value.next_attempt_at,
            Some(stale_participant_cleanup_next_attempt_at(observed_at))
        );
        let pending_claim = pending_workflow
            .value
            .runner_claim
            .as_ref()
            .unwrap_or_else(|| panic!("missing pending workflow runner claim"));
        assert_eq!(pending_claim.runner_id, registration_key);
        assert_eq!(pending_claim.claimed_at, observed_at);
        assert_eq!(pending_claim.last_heartbeat_at, observed_at);
        assert_eq!(
            pending_claim.lease_expires_at,
            observed_at + stale_participant_cleanup_runner_lease_duration()
        );
        assert!(!pending_claim.fencing_token.is_empty());
        assert!(
            pending_workflow
                .value
                .steps
                .iter()
                .all(|step| step.state == WorkflowStepState::Pending)
        );
        let pending_fencing_token = pending_claim.fencing_token.clone();

        let topology_handle = RuntimeTopologyHandle::new(topology_seed.clone());
        let context = RuntimeProcessRegistrationContext {
            store: registration_store.clone(),
            cell_directory_store: cell_directory_store.clone(),
            service_group_directory_store: CellServiceGroupDirectoryCollection::open_local(
                runtime_service_group_directory_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            cleanup_workflow_store: cleanup_workflow_store.clone(),
            registry_reconciler: registry_reconciler.clone(),
            tombstone_history_store,
            audit_log,
            outbox,
            publication_plan: publication_plan.clone(),
            topology_handle: topology_handle.clone(),
            readyz_handle: RuntimeReadyzHandle::default(),
            current_fencing_token: Arc::new(Mutex::new(registration.fencing_token.clone())),
        };
        let preflight_observed_at = observed_at + time::Duration::seconds(5);
        let preflight_directory = activate_runtime_cell_directory(
            &cell_directory_store,
            &registration_store,
            &cleanup_workflow_store,
            &registry_reconciler,
            &registration,
            preflight_observed_at,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let preflight_workflow = cleanup_workflow_store
            .get(cleanup_workflow_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing preflight-confirmed cleanup workflow"));
        assert_eq!(preflight_workflow.value.phase, WorkflowPhase::Running);
        assert_eq!(preflight_workflow.value.current_step_index, Some(1));
        assert_eq!(
            preflight_workflow.value.state.stage,
            StaleParticipantCleanupStage::PreflightConfirmed
        );
        assert_eq!(preflight_workflow.value.state.review_observations, 2);
        let preflight_confirmed_at = preflight_workflow
            .value
            .state
            .preflight_confirmed_at
            .unwrap_or_else(|| panic!("missing preflight-confirmed timestamp"));
        let preflight_route_withdrawal = preflight_workflow
            .value
            .state
            .route_withdrawal
            .as_ref()
            .unwrap_or_else(|| panic!("missing route-withdrawal artifact"));
        let preflight_target_readiness = preflight_workflow
            .value
            .state
            .target_readiness
            .as_ref()
            .unwrap_or_else(|| panic!("missing target-readiness artifact"));
        let preflight_rollback = preflight_workflow
            .value
            .state
            .rollback
            .as_ref()
            .unwrap_or_else(|| panic!("missing rollback artifact"));
        assert!(
            preflight_workflow
                .value
                .state
                .tombstone_eligible_at
                .is_none()
        );
        assert_eq!(
            preflight_workflow.value.steps[0].state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            preflight_workflow.value.steps[1].state,
            WorkflowStepState::Active
        );
        assert_eq!(
            preflight_workflow.value.steps[2].state,
            WorkflowStepState::Pending
        );
        assert_eq!(
            preflight_route_withdrawal.source_participant_registration_id,
            stale_peer_key
        );
        assert_eq!(
            preflight_route_withdrawal.service_groups,
            stale_peer_participant.service_groups
        );
        assert_eq!(
            preflight_route_withdrawal.prepared_at,
            preflight_observed_at
        );
        assert_eq!(
            preflight_target_readiness.source_participant_registration_id,
            stale_peer_key
        );
        assert_eq!(
            preflight_target_readiness.target_participant_registration_id,
            registration_key
        );
        assert_eq!(
            preflight_target_readiness.service_groups,
            stale_peer_participant.service_groups
        );
        assert_eq!(
            preflight_target_readiness.prepared_at,
            preflight_observed_at
        );
        assert_eq!(
            preflight_rollback.source_participant_registration_id,
            stale_peer_key
        );
        assert_eq!(
            preflight_rollback.target_participant_registration_id,
            registration_key
        );
        assert_eq!(
            preflight_rollback.service_groups,
            stale_peer_participant.service_groups
        );
        assert_eq!(preflight_rollback.prepared_at, preflight_observed_at);
        assert_eq!(
            preflight_workflow.value.next_attempt_at,
            Some(stale_participant_cleanup_next_attempt_at(
                preflight_observed_at
            ))
        );
        let preflight_claim = preflight_workflow
            .value
            .runner_claim
            .as_ref()
            .unwrap_or_else(|| panic!("missing preflight workflow runner claim"));
        assert_eq!(preflight_claim.runner_id, registration_key);
        assert_eq!(preflight_claim.claimed_at, observed_at);
        assert_eq!(preflight_claim.last_heartbeat_at, preflight_observed_at);
        assert_eq!(
            preflight_claim.lease_expires_at,
            preflight_observed_at + stale_participant_cleanup_runner_lease_duration()
        );
        assert_eq!(preflight_claim.fencing_token, pending_fencing_token);
        context
            .publish(&registration, &preflight_directory, preflight_observed_at)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let preflight_topology = topology_handle.snapshot();
        assert!(preflight_topology.tombstone_history.is_empty());
        let published_current = preflight_topology
            .participants
            .iter()
            .find(|participant| participant.registration_id == registration_key)
            .unwrap_or_else(|| panic!("missing published current participant"));
        let published_current_state = published_current
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing published current participant state"));
        let published_current_reconciliation = published_current
            .reconciliation
            .as_ref()
            .unwrap_or_else(|| panic!("missing published current participant reconciliation"));
        assert_eq!(
            published_current_state.readiness,
            RuntimeReadinessState::Ready
        );
        assert_eq!(
            published_current_state.drain_intent,
            RuntimeDrainIntent::Serving
        );
        assert_eq!(
            published_current_state.lease.freshness,
            RuntimeLeaseFreshness::Fresh
        );
        assert!(published_current_reconciliation.stale_since.is_none());
        assert!(published_current_reconciliation.cleanup_workflow.is_none());

        let published_stale_peer = preflight_topology
            .participants
            .iter()
            .find(|participant| participant.registration_id == stale_peer_key)
            .unwrap_or_else(|| panic!("missing published stale peer participant"));
        let published_stale_peer_state = published_stale_peer
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing published stale peer participant state"));
        let published_stale_peer_reconciliation = published_stale_peer
            .reconciliation
            .as_ref()
            .unwrap_or_else(|| panic!("missing published stale peer participant reconciliation"));
        let published_cleanup_workflow = published_stale_peer_reconciliation
            .cleanup_workflow
            .as_ref()
            .unwrap_or_else(|| panic!("missing published cleanup workflow"));
        assert_eq!(
            published_stale_peer_state.readiness,
            RuntimeReadinessState::Ready
        );
        assert_eq!(
            published_stale_peer_state.drain_intent,
            RuntimeDrainIntent::Draining
        );
        assert_eq!(
            published_stale_peer_state.lease.freshness,
            RuntimeLeaseFreshness::Expired
        );
        assert!(published_stale_peer_reconciliation.stale_since.is_some());
        assert_eq!(published_cleanup_workflow.id, cleanup_workflow_id);
        assert_eq!(
            published_cleanup_workflow.workflow_kind,
            "runtime.participant.cleanup.v1"
        );
        assert_eq!(published_cleanup_workflow.phase, "running");
        assert_eq!(
            published_cleanup_workflow.stage,
            RuntimeParticipantCleanupStage::PreflightConfirmed
        );
        assert_eq!(published_cleanup_workflow.review_observations, 2);
        assert_eq!(
            published_cleanup_workflow.preflight_confirmed_at,
            Some(preflight_confirmed_at)
        );
        assert_eq!(
            published_cleanup_workflow
                .route_withdrawal
                .as_ref()
                .map(|artifact| {
                    (
                        artifact.source_participant_registration_id.clone(),
                        artifact.service_groups.clone(),
                        artifact.prepared_at,
                    )
                }),
            Some((
                stale_peer_key.clone(),
                stale_peer_participant.service_groups.clone(),
                preflight_observed_at,
            ))
        );
        assert_eq!(
            published_cleanup_workflow
                .target_readiness
                .as_ref()
                .map(|artifact| {
                    (
                        artifact.source_participant_registration_id.clone(),
                        artifact.target_participant_registration_id.clone(),
                        artifact.service_groups.clone(),
                        artifact.prepared_at,
                    )
                }),
            Some((
                stale_peer_key.clone(),
                registration_key.clone(),
                stale_peer_participant.service_groups.clone(),
                preflight_observed_at,
            ))
        );
        assert_eq!(
            published_cleanup_workflow
                .rollback
                .as_ref()
                .map(|artifact| {
                    (
                        artifact.source_participant_registration_id.clone(),
                        artifact.target_participant_registration_id.clone(),
                        artifact.service_groups.clone(),
                        artifact.prepared_at,
                    )
                }),
            Some((
                stale_peer_key.clone(),
                registration_key.clone(),
                stale_peer_participant.service_groups.clone(),
                preflight_observed_at,
            ))
        );
        assert_eq!(published_cleanup_workflow.tombstone_eligible_at, None);

        let tombstone_observed_at = preflight_observed_at + time::Duration::seconds(5);
        let tombstone_directory = activate_runtime_cell_directory(
            &cell_directory_store,
            &registration_store,
            &cleanup_workflow_store,
            &registry_reconciler,
            &registration,
            tombstone_observed_at,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let tombstone_healthy_participant = tombstone_directory
            .participants
            .iter()
            .find(|participant| participant.registration_id == registration_key)
            .unwrap_or_else(|| panic!("missing healthy participant after tombstone review"));
        let tombstone_healthy_reconciliation = tombstone_healthy_participant
            .reconciliation
            .as_ref()
            .unwrap_or_else(|| panic!("missing healthy participant reconciliation"));
        assert!(
            tombstone_healthy_reconciliation
                .cleanup_workflow_id
                .is_none()
        );

        let tombstone_workflow = cleanup_workflow_store
            .get(cleanup_workflow_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing tombstone-eligible cleanup workflow"));
        assert_eq!(tombstone_workflow.value.phase, WorkflowPhase::Running);
        assert_eq!(tombstone_workflow.value.current_step_index, Some(2));
        assert_eq!(
            tombstone_workflow.value.state.stage,
            StaleParticipantCleanupStage::TombstoneEligible
        );
        assert_eq!(tombstone_workflow.value.state.review_observations, 3);
        assert_eq!(
            tombstone_workflow.value.state.preflight_confirmed_at,
            Some(preflight_confirmed_at)
        );
        let tombstone_eligible_at = tombstone_workflow
            .value
            .state
            .tombstone_eligible_at
            .unwrap_or_else(|| panic!("missing tombstone-eligible timestamp"));
        let tombstone_route_withdrawal = tombstone_workflow
            .value
            .state
            .route_withdrawal
            .as_ref()
            .unwrap_or_else(|| panic!("missing tombstone route-withdrawal artifact"));
        let tombstone_target_readiness = tombstone_workflow
            .value
            .state
            .target_readiness
            .as_ref()
            .unwrap_or_else(|| panic!("missing tombstone target-readiness artifact"));
        let tombstone_rollback = tombstone_workflow
            .value
            .state
            .rollback
            .as_ref()
            .unwrap_or_else(|| panic!("missing tombstone rollback artifact"));
        assert_eq!(
            tombstone_workflow.value.steps[0].state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            tombstone_workflow.value.steps[1].state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            tombstone_workflow.value.steps[2].state,
            WorkflowStepState::Active
        );
        assert_eq!(
            tombstone_route_withdrawal.source_participant_registration_id,
            stale_peer_key
        );
        assert_eq!(
            tombstone_route_withdrawal.service_groups,
            stale_peer_participant.service_groups
        );
        assert_eq!(
            tombstone_route_withdrawal.prepared_at,
            preflight_observed_at
        );
        assert_eq!(
            tombstone_target_readiness.source_participant_registration_id,
            stale_peer_key
        );
        assert_eq!(
            tombstone_target_readiness.target_participant_registration_id,
            registration_key
        );
        assert_eq!(
            tombstone_target_readiness.service_groups,
            stale_peer_participant.service_groups
        );
        assert_eq!(
            tombstone_target_readiness.prepared_at,
            preflight_observed_at
        );
        assert_eq!(
            tombstone_rollback.source_participant_registration_id,
            stale_peer_key
        );
        assert_eq!(
            tombstone_rollback.target_participant_registration_id,
            registration_key
        );
        assert_eq!(
            tombstone_rollback.service_groups,
            stale_peer_participant.service_groups
        );
        assert_eq!(tombstone_rollback.prepared_at, preflight_observed_at);
        assert_eq!(tombstone_workflow.value.next_attempt_at, None);
        let tombstone_claim = tombstone_workflow
            .value
            .runner_claim
            .as_ref()
            .unwrap_or_else(|| panic!("missing tombstone workflow runner claim"));
        assert_eq!(tombstone_claim.runner_id, registration_key);
        assert_eq!(tombstone_claim.claimed_at, observed_at);
        assert_eq!(tombstone_claim.last_heartbeat_at, tombstone_observed_at);
        assert_eq!(
            tombstone_claim.lease_expires_at,
            tombstone_observed_at + stale_participant_cleanup_runner_lease_duration()
        );
        assert_eq!(tombstone_claim.fencing_token, pending_fencing_token);

        context
            .publish(&registration, &tombstone_directory, tombstone_observed_at)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let tombstone_topology = topology_handle.snapshot();
        assert!(tombstone_topology.tombstone_history.is_empty());
        let published_tombstone_peer = tombstone_topology
            .participants
            .iter()
            .find(|participant| participant.registration_id == stale_peer_key)
            .unwrap_or_else(|| panic!("missing tombstone-reviewed stale peer participant"));
        let published_tombstone_reconciliation = published_tombstone_peer
            .reconciliation
            .as_ref()
            .unwrap_or_else(|| panic!("missing tombstone-reviewed stale peer reconciliation"));
        let published_tombstone_workflow = published_tombstone_reconciliation
            .cleanup_workflow
            .as_ref()
            .unwrap_or_else(|| panic!("missing tombstone-reviewed cleanup workflow"));
        assert_eq!(published_tombstone_workflow.phase, "running");
        assert_eq!(
            published_tombstone_workflow.stage,
            RuntimeParticipantCleanupStage::TombstoneEligible
        );
        assert_eq!(published_tombstone_workflow.review_observations, 3);
        assert_eq!(
            published_tombstone_workflow.preflight_confirmed_at,
            Some(preflight_confirmed_at)
        );
        assert_eq!(
            published_tombstone_workflow
                .route_withdrawal
                .as_ref()
                .map(|artifact| {
                    (
                        artifact.source_participant_registration_id.clone(),
                        artifact.service_groups.clone(),
                        artifact.prepared_at,
                    )
                }),
            Some((
                stale_peer_key,
                stale_peer_participant.service_groups.clone(),
                preflight_observed_at,
            ))
        );
        assert_eq!(
            published_tombstone_workflow
                .target_readiness
                .as_ref()
                .map(|artifact| {
                    (
                        artifact.source_participant_registration_id.clone(),
                        artifact.target_participant_registration_id.clone(),
                        artifact.service_groups.clone(),
                        artifact.prepared_at,
                    )
                }),
            Some((
                String::from("controller:stale-peer-node"),
                registration_key.clone(),
                stale_peer_participant.service_groups.clone(),
                preflight_observed_at,
            ))
        );
        assert_eq!(
            published_tombstone_workflow
                .rollback
                .as_ref()
                .map(|artifact| {
                    (
                        artifact.source_participant_registration_id.clone(),
                        artifact.target_participant_registration_id.clone(),
                        artifact.service_groups.clone(),
                        artifact.prepared_at,
                    )
                }),
            Some((
                String::from("controller:stale-peer-node"),
                registration_key,
                stale_peer_participant.service_groups.clone(),
                preflight_observed_at,
            ))
        );
        assert_eq!(
            published_tombstone_workflow.tombstone_eligible_at,
            Some(tombstone_eligible_at)
        );
    }

    #[tokio::test]
    async fn runtime_cell_directory_activation_restores_cleanup_progress_from_durable_workflow_state()
     {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let state_dir = state
            .create_dir_all("state")
            .unwrap_or_else(|error| panic!("{error}"));
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::Distributed,
                node_name: String::from("controller-cleanup-replay-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: state_dir.display().to_string(),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig {
                process_role: Some(RuntimeProcessRole::Controller.as_str().to_owned()),
                forward_targets: BTreeMap::new(),
            },
        };

        let publication_plan = publication_plan_for_test(&config);
        assert!(publication_plan.owns_runtime_registry_reconciliation());
        let placement = config
            .runtime_cell_placement()
            .unwrap_or_else(|error| panic!("{error}"));
        let registration_store =
            LeaseRegistrationCollection::open_local(runtime_registration_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store =
            CellDirectoryCollection::open_local(runtime_cell_directory_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cleanup_workflow_store =
            WorkflowCollection::<StaleParticipantCleanupWorkflowState>::open_local(
                runtime_stale_participant_cleanup_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let registry_reconciler =
            runtime_registry_reconciler_for_test(&state_dir, &publication_plan).await;

        let stale_peer_key =
            runtime_registration_key(RuntimeProcessRole::Controller, "stale-peer-node");
        let stale_peer_publication_plan =
            runtime_role_activation_plan(RuntimeProcessRole::Controller).publication_plan(
                config.schema.mode,
                String::from("stale-peer-node"),
                placement.region_membership(),
                placement.cell_membership(),
            );
        let _stale_peer_registration =
            activate_runtime_registration(&registration_store, &stale_peer_publication_plan)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let stale_lease_renewed_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(60);
        let stale_lease_expires_at = stale_lease_renewed_at
            + time::Duration::seconds(i64::from(RUNTIME_PROCESS_LEASE_DURATION_SECONDS));
        let stale_peer_registration = mutate_runtime_registration(
            &registration_store,
            stale_peer_key.as_str(),
            |registration| {
                registration.set_drain_intent(LeaseDrainIntent::Draining);
                registration.lease_renewed_at = stale_lease_renewed_at;
                registration.lease_expires_at = stale_lease_expires_at;
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_or_else(|| panic!("missing stale peer registration"));

        let mut seeded_peer = stale_peer_publication_plan
            .cell_participant(&stale_peer_registration, time::OffsetDateTime::now_utc());
        seeded_peer.reconciliation = None;
        let seeded_directory = CellDirectoryRecord::new(
            placement.cell_id.clone(),
            placement.cell_name.clone(),
            placement.region_record(),
        )
        .with_participant(seeded_peer.clone());
        cell_directory_store
            .upsert(placement.cell_id.as_str(), seeded_directory, None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stale_since = time::OffsetDateTime::now_utc() - time::Duration::seconds(45);
        let cleanup_observed_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(10);
        let pending_workflow = stale_participant_cleanup_workflow(
            placement.cell_id.clone(),
            &seeded_peer,
            stale_since,
            cleanup_observed_at,
        );
        let cleanup_workflow_id = pending_workflow.id.clone();
        cleanup_workflow_store
            .create(cleanup_workflow_id.as_str(), pending_workflow)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let registration = activate_runtime_registration(&registration_store, &publication_plan)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let registration_key = publication_plan.registration_key().to_owned();
        let observed_at = time::OffsetDateTime::now_utc();
        let directory = activate_runtime_cell_directory(
            &cell_directory_store,
            &registration_store,
            &cleanup_workflow_store,
            &registry_reconciler,
            &registration,
            observed_at,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let stale_peer_participant = directory
            .participants
            .iter()
            .find(|participant| participant.registration_id == stale_peer_key)
            .unwrap_or_else(|| panic!("missing stale peer participant"));
        let reconciliation = stale_peer_participant
            .reconciliation
            .as_ref()
            .unwrap_or_else(|| panic!("missing stale peer reconciliation"));
        assert_eq!(reconciliation.stale_since, Some(stale_since));
        assert_eq!(
            reconciliation.cleanup_workflow_id.as_deref(),
            Some(cleanup_workflow_id.as_str())
        );

        let stored_workflow = cleanup_workflow_store
            .get(cleanup_workflow_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing durable cleanup workflow"));
        assert_eq!(stored_workflow.value.phase, WorkflowPhase::Running);
        assert_eq!(stored_workflow.value.current_step_index, Some(1));
        assert_eq!(
            stored_workflow.value.state.stage,
            StaleParticipantCleanupStage::PreflightConfirmed
        );
        assert_eq!(stored_workflow.value.state.review_observations, 2);
        assert_eq!(stored_workflow.value.state.stale_since, stale_since);
        assert_eq!(
            stored_workflow.value.state.last_observed_stale_at,
            observed_at
        );
        assert!(stored_workflow.value.state.preflight_confirmed_at.is_some());
        assert!(stored_workflow.value.state.tombstone_eligible_at.is_none());
        assert_eq!(
            stored_workflow.value.next_attempt_at,
            Some(stale_participant_cleanup_next_attempt_at(observed_at))
        );
        let stored_claim = stored_workflow
            .value
            .runner_claim
            .as_ref()
            .unwrap_or_else(|| panic!("missing replayed workflow runner claim"));
        assert_eq!(stored_claim.runner_id, registration_key);
        assert_eq!(stored_claim.last_heartbeat_at, observed_at);
        assert_eq!(
            stored_claim.lease_expires_at,
            observed_at + stale_participant_cleanup_runner_lease_duration()
        );
    }

    #[tokio::test]
    async fn runtime_cell_directory_activation_blocks_cleanup_until_runner_claim_expires_then_takes_over()
     {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let state_dir = state
            .create_dir_all("state")
            .unwrap_or_else(|error| panic!("{error}"));
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::Distributed,
                node_name: String::from("controller-cleanup-takeover-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: state_dir.display().to_string(),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig {
                process_role: Some(RuntimeProcessRole::Controller.as_str().to_owned()),
                forward_targets: BTreeMap::new(),
            },
        };

        let publication_plan = publication_plan_for_test(&config);
        assert!(publication_plan.owns_runtime_registry_reconciliation());
        let placement = config
            .runtime_cell_placement()
            .unwrap_or_else(|error| panic!("{error}"));
        let registration_store =
            LeaseRegistrationCollection::open_local(runtime_registration_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store =
            CellDirectoryCollection::open_local(runtime_cell_directory_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cleanup_workflow_store =
            WorkflowCollection::<StaleParticipantCleanupWorkflowState>::open_local(
                runtime_stale_participant_cleanup_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let registry_reconciler =
            runtime_registry_reconciler_for_test(&state_dir, &publication_plan).await;

        let stale_peer_key =
            runtime_registration_key(RuntimeProcessRole::Controller, "claimed-stale-peer-node");
        let stale_peer_publication_plan =
            runtime_role_activation_plan(RuntimeProcessRole::Controller).publication_plan(
                config.schema.mode,
                String::from("claimed-stale-peer-node"),
                placement.region_membership(),
                placement.cell_membership(),
            );
        let _stale_peer_registration =
            activate_runtime_registration(&registration_store, &stale_peer_publication_plan)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let stale_lease_renewed_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(60);
        let stale_lease_expires_at = stale_lease_renewed_at
            + time::Duration::seconds(i64::from(RUNTIME_PROCESS_LEASE_DURATION_SECONDS));
        let stale_peer_registration = mutate_runtime_registration(
            &registration_store,
            stale_peer_key.as_str(),
            |registration| {
                registration.set_drain_intent(LeaseDrainIntent::Draining);
                registration.lease_renewed_at = stale_lease_renewed_at;
                registration.lease_expires_at = stale_lease_expires_at;
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_or_else(|| panic!("missing stale peer registration"));

        let seeded_peer = stale_peer_publication_plan
            .cell_participant(&stale_peer_registration, time::OffsetDateTime::now_utc());
        let seeded_directory = CellDirectoryRecord::new(
            placement.cell_id.clone(),
            placement.cell_name.clone(),
            placement.region_record(),
        )
        .with_participant(seeded_peer.clone());
        cell_directory_store
            .upsert(placement.cell_id.as_str(), seeded_directory, None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stale_since = time::OffsetDateTime::now_utc() - time::Duration::seconds(45);
        let claimed_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(10);
        let blocked_observed_at = claimed_at + stale_participant_cleanup_retry_interval();
        let mut claimed_workflow = stale_participant_cleanup_workflow(
            placement.cell_id.clone(),
            &seeded_peer,
            stale_since,
            claimed_at,
        );
        claimed_workflow
            .claim_runner_at(
                "controller:other-active-runner",
                stale_participant_cleanup_runner_lease_duration(),
                claimed_at,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        claimed_workflow.set_next_attempt_at(Some(blocked_observed_at), claimed_at);
        let cleanup_workflow_id = claimed_workflow.id.clone();
        let original_claim = claimed_workflow
            .runner_claim
            .clone()
            .unwrap_or_else(|| panic!("missing seeded workflow claim"));
        cleanup_workflow_store
            .create(cleanup_workflow_id.as_str(), claimed_workflow)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let registration = activate_runtime_registration(&registration_store, &publication_plan)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let registration_key = publication_plan.registration_key().to_owned();
        let blocked_directory = activate_runtime_cell_directory(
            &cell_directory_store,
            &registration_store,
            &cleanup_workflow_store,
            &registry_reconciler,
            &registration,
            blocked_observed_at,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let blocked_participant = blocked_directory
            .participants
            .iter()
            .find(|participant| participant.registration_id == stale_peer_key)
            .unwrap_or_else(|| panic!("missing blocked stale peer participant"));
        let blocked_reconciliation = blocked_participant
            .reconciliation
            .as_ref()
            .unwrap_or_else(|| panic!("missing blocked stale peer reconciliation"));
        assert_eq!(blocked_reconciliation.stale_since, Some(stale_since));
        assert_eq!(
            blocked_reconciliation.cleanup_workflow_id.as_deref(),
            Some(cleanup_workflow_id.as_str())
        );

        let blocked_workflow = cleanup_workflow_store
            .get(cleanup_workflow_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing blocked workflow"));
        assert_eq!(blocked_workflow.value.phase, WorkflowPhase::Pending);
        assert_eq!(blocked_workflow.value.state.review_observations, 1);
        assert_eq!(
            blocked_workflow.value.state.last_observed_stale_at,
            claimed_at
        );
        assert_eq!(
            blocked_workflow.value.next_attempt_at,
            Some(blocked_observed_at)
        );
        let blocked_claim = blocked_workflow
            .value
            .runner_claim
            .as_ref()
            .unwrap_or_else(|| panic!("missing blocked workflow claim"));
        assert_eq!(blocked_claim.runner_id, "controller:other-active-runner");
        assert_eq!(blocked_claim.fencing_token, original_claim.fencing_token);
        assert_eq!(blocked_claim.takeover_count, 0);

        let takeover_observed_at = claimed_at
            + stale_participant_cleanup_runner_lease_duration()
            + time::Duration::seconds(1);
        let takeover_directory = activate_runtime_cell_directory(
            &cell_directory_store,
            &registration_store,
            &cleanup_workflow_store,
            &registry_reconciler,
            &registration,
            takeover_observed_at,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let takeover_participant = takeover_directory
            .participants
            .iter()
            .find(|participant| participant.registration_id == stale_peer_key)
            .unwrap_or_else(|| panic!("missing takeover stale peer participant"));
        let takeover_reconciliation = takeover_participant
            .reconciliation
            .as_ref()
            .unwrap_or_else(|| panic!("missing takeover stale peer reconciliation"));
        assert_eq!(takeover_reconciliation.stale_since, Some(stale_since));
        assert_eq!(
            takeover_reconciliation.cleanup_workflow_id.as_deref(),
            Some(cleanup_workflow_id.as_str())
        );

        let takeover_workflow = cleanup_workflow_store
            .get(cleanup_workflow_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing takeover workflow"));
        assert_eq!(takeover_workflow.value.phase, WorkflowPhase::Running);
        assert_eq!(takeover_workflow.value.current_step_index, Some(1));
        assert_eq!(
            takeover_workflow.value.state.stage,
            StaleParticipantCleanupStage::PreflightConfirmed
        );
        assert_eq!(takeover_workflow.value.state.review_observations, 2);
        assert_eq!(
            takeover_workflow.value.state.last_observed_stale_at,
            takeover_observed_at
        );
        assert_eq!(
            takeover_workflow.value.next_attempt_at,
            Some(stale_participant_cleanup_next_attempt_at(
                takeover_observed_at
            ))
        );
        let takeover_claim = takeover_workflow
            .value
            .runner_claim
            .as_ref()
            .unwrap_or_else(|| panic!("missing takeover workflow claim"));
        assert_eq!(takeover_claim.runner_id, registration_key);
        assert_eq!(takeover_claim.claimed_at, takeover_observed_at);
        assert_eq!(takeover_claim.last_heartbeat_at, takeover_observed_at);
        assert_eq!(
            takeover_claim.lease_expires_at,
            takeover_observed_at + stale_participant_cleanup_runner_lease_duration()
        );
        assert_eq!(takeover_claim.takeover_count, 1);
        assert_ne!(takeover_claim.fencing_token, original_claim.fencing_token);
    }

    #[tokio::test]
    async fn runtime_process_registration_context_publishes_ready_and_draining_state() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let state_dir = state
            .create_dir_all("state")
            .unwrap_or_else(|error| panic!("{error}"));
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("registration-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: state_dir.display().to_string(),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let publication_plan = publication_plan_for_test(&config);
        let topology_seed = publication_plan.topology_seed();
        let placement = config
            .runtime_cell_placement()
            .unwrap_or_else(|error| panic!("{error}"));
        let registration_store =
            LeaseRegistrationCollection::open_local(runtime_registration_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store =
            CellDirectoryCollection::open_local(runtime_cell_directory_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cleanup_workflow_store =
            WorkflowCollection::<StaleParticipantCleanupWorkflowState>::open_local(
                runtime_stale_participant_cleanup_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let tombstone_history_store = ParticipantTombstoneHistoryCollection::open(
            runtime_participant_tombstone_history_store_path(&state_dir),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let audit_log = AuditLog::open(runtime_audit_log_path(&state_dir))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let outbox = DurableEventRelay::<PlatformEvent>::open(runtime_outbox_path(&state_dir))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let registry_reconciler =
            runtime_registry_reconciler_for_test(&state_dir, &publication_plan).await;
        let registration_key = publication_plan.registration_key().to_owned();
        let registration = activate_runtime_registration(&registration_store, &publication_plan)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(registration.subject_kind, RUNTIME_PROCESS_SUBJECT_KIND);
        assert_eq!(registration.incarnation, 1);
        assert_eq!(registration.readiness, LeaseReadiness::Ready);
        assert_eq!(registration.drain_intent, LeaseDrainIntent::Serving);
        assert!(!registration.fencing_token.is_empty());

        let initial_observed_at = time::OffsetDateTime::now_utc();
        let cell_directory = activate_runtime_cell_directory(
            &cell_directory_store,
            &registration_store,
            &cleanup_workflow_store,
            &registry_reconciler,
            &registration,
            initial_observed_at,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let topology_handle = RuntimeTopologyHandle::new(topology_seed.clone());
        let context = RuntimeProcessRegistrationContext {
            store: registration_store.clone(),
            cell_directory_store: cell_directory_store.clone(),
            service_group_directory_store: CellServiceGroupDirectoryCollection::open_local(
                runtime_service_group_directory_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            cleanup_workflow_store: cleanup_workflow_store.clone(),
            registry_reconciler: registry_reconciler.clone(),
            tombstone_history_store,
            audit_log,
            outbox,
            publication_plan: publication_plan.clone(),
            topology_handle: topology_handle.clone(),
            readyz_handle: RuntimeReadyzHandle::default(),
            current_fencing_token: Arc::new(Mutex::new(registration.fencing_token.clone())),
        };
        context
            .publish(&registration, &cell_directory, initial_observed_at)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let published_topology = topology_handle.snapshot();
        assert!(published_topology.tombstone_history.is_empty());
        let published_edge_directory = published_topology
            .service_group_directory
            .iter()
            .find(|entry| entry.group == RuntimeLogicalServiceGroup::Edge)
            .unwrap_or_else(|| panic!("missing published edge service-group directory"));
        let published_state = published_topology
            .process_state
            .unwrap_or_else(|| panic!("missing published process state"));
        assert_eq!(published_state.registration_id, registration_key);
        assert_eq!(published_state.readiness, RuntimeReadinessState::Ready);
        assert_eq!(published_state.drain_intent, RuntimeDrainIntent::Serving);
        assert_eq!(
            published_state.lease.freshness,
            RuntimeLeaseFreshness::Fresh
        );

        let published_participant = published_topology
            .participants
            .iter()
            .find(|participant| participant.registration_id == registration_key)
            .unwrap_or_else(|| panic!("missing published participant"));
        let published_participant_state = published_participant
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing published participant state"));
        assert_eq!(
            published_participant_state.readiness,
            RuntimeReadinessState::Ready
        );
        assert_eq!(
            published_participant_state.drain_intent,
            RuntimeDrainIntent::Serving
        );
        assert_eq!(
            published_participant_state.drain_phase,
            RuntimeParticipantDrainPhase::Serving
        );
        assert!(
            published_participant_state
                .takeover_registration_id
                .is_none()
        );
        assert!(
            published_participant_state
                .takeover_acknowledged_at
                .is_none()
        );
        assert_eq!(
            published_participant_state.lease.freshness,
            RuntimeLeaseFreshness::Fresh
        );
        assert_eq!(
            published_edge_directory.resolved_registration_ids,
            vec![registration_key.clone()]
        );
        assert!(published_edge_directory.registrations[0].healthy);

        let stale_registration = mutate_runtime_registration(
            &registration_store,
            registration_key.as_str(),
            |registration| {
                registration.set_readiness(LeaseReadiness::Starting);
                registration.set_drain_intent(LeaseDrainIntent::Draining);
                registration.expire_now();
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_or_else(|| panic!("missing registration to stale"));
        let stale_observed_at = time::OffsetDateTime::now_utc();
        let stale_cell_directory = activate_runtime_cell_directory(
            &cell_directory_store,
            &registration_store,
            &cleanup_workflow_store,
            &registry_reconciler,
            &stale_registration,
            stale_observed_at,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let stale_participant = stale_cell_directory
            .participants
            .iter()
            .find(|participant| participant.registration_id == registration_key)
            .unwrap_or_else(|| panic!("missing stale self participant"));
        let stale_participant_reconciliation = stale_participant
            .reconciliation
            .as_ref()
            .unwrap_or_else(|| panic!("missing stale self participant reconciliation"));
        assert!(stale_participant_reconciliation.stale_since.is_some());
        assert!(
            stale_participant_reconciliation
                .cleanup_workflow_id
                .is_none()
        );
        context
            .publish(
                &stale_registration,
                &stale_cell_directory,
                stale_observed_at,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        context
            .renew()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let renewed = registration_store
            .get(registration_key.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing renewed registration"));
        assert_eq!(renewed.value.readiness, LeaseReadiness::Ready);
        assert_eq!(renewed.value.drain_intent, LeaseDrainIntent::Serving);
        assert_eq!(
            renewed
                .value
                .lease_freshness_at(time::OffsetDateTime::now_utc()),
            LeaseFreshness::Fresh
        );

        let renewed_directory = cell_directory_store
            .get(placement.cell_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing renewed cell directory"));
        let renewed_participant = renewed_directory
            .value
            .participants
            .iter()
            .find(|participant| participant.registration_id == registration_key)
            .unwrap_or_else(|| panic!("missing renewed participant"));
        let renewed_participant_state = renewed_participant
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing renewed participant state"));
        assert_eq!(renewed_participant_state.readiness, LeaseReadiness::Ready);
        assert_eq!(
            renewed_participant_state.drain_intent,
            LeaseDrainIntent::Serving
        );
        assert_eq!(
            renewed_participant_state.lease.freshness,
            LeaseFreshness::Fresh
        );

        let renewed_topology = topology_handle.snapshot();
        let renewed_topology_participant = renewed_topology
            .participants
            .iter()
            .find(|participant| participant.registration_id == registration_key)
            .unwrap_or_else(|| panic!("missing renewed topology participant"));
        let renewed_topology_state = renewed_topology_participant
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing renewed topology participant state"));
        assert_eq!(
            renewed_topology_state.readiness,
            RuntimeReadinessState::Ready
        );
        assert_eq!(
            renewed_topology_state.drain_intent,
            RuntimeDrainIntent::Serving
        );
        assert_eq!(
            renewed_topology_state.drain_phase,
            RuntimeParticipantDrainPhase::Serving
        );
        assert_eq!(
            renewed_topology_state.lease.freshness,
            RuntimeLeaseFreshness::Fresh
        );

        context
            .request_drain()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let drained = registration_store
            .get(registration_key.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing drained registration"));
        assert_eq!(drained.value.drain_intent, LeaseDrainIntent::Draining);
        assert_eq!(
            drained
                .value
                .lease_freshness_at(time::OffsetDateTime::now_utc()),
            LeaseFreshness::Fresh
        );

        let drained_state = topology_handle
            .snapshot()
            .process_state
            .unwrap_or_else(|| panic!("missing drained process state"));
        assert_eq!(drained_state.readiness, RuntimeReadinessState::Ready);
        assert_eq!(drained_state.drain_intent, RuntimeDrainIntent::Draining);
        assert_eq!(drained_state.lease.freshness, RuntimeLeaseFreshness::Fresh);

        let drained_directory = cell_directory_store
            .get(placement.cell_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing drained cell directory"));
        let drained_participant = drained_directory
            .value
            .participants
            .iter()
            .find(|participant| participant.registration_id == registration_key)
            .unwrap_or_else(|| panic!("missing drained participant"));
        let drained_participant_state = drained_participant
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing drained participant state"));
        let drained_participant_reconciliation = drained_participant
            .reconciliation
            .as_ref()
            .unwrap_or_else(|| panic!("missing drained participant reconciliation"));
        assert_eq!(drained_participant_state.readiness, LeaseReadiness::Ready);
        assert_eq!(
            drained_participant_state.drain_intent,
            LeaseDrainIntent::Draining
        );
        assert_eq!(
            drained_participant_state.drain_phase,
            CellParticipantDrainPhase::TakeoverPending
        );
        assert!(drained_participant_state.takeover_registration_id.is_none());
        assert!(drained_participant_state.takeover_acknowledged_at.is_none());
        assert_eq!(
            drained_participant_state.lease.freshness,
            LeaseFreshness::Fresh
        );
        assert!(drained_participant_reconciliation.stale_since.is_none());
        assert!(
            drained_participant_reconciliation
                .cleanup_workflow_id
                .is_none()
        );

        let drained_topology = topology_handle.snapshot();
        let drained_edge_directory = drained_topology
            .service_group_directory
            .iter()
            .find(|entry| entry.group == RuntimeLogicalServiceGroup::Edge)
            .unwrap_or_else(|| panic!("missing drained edge service-group directory"));
        let drained_topology_participant = drained_topology
            .participants
            .iter()
            .find(|participant| participant.registration_id == registration_key)
            .unwrap_or_else(|| panic!("missing drained topology participant"));
        let drained_topology_state = drained_topology_participant
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing drained topology participant state"));
        let drained_topology_reconciliation = drained_topology_participant
            .reconciliation
            .as_ref()
            .unwrap_or_else(|| panic!("missing drained topology participant reconciliation"));
        assert_eq!(
            drained_topology_state.readiness,
            RuntimeReadinessState::Ready
        );
        assert_eq!(
            drained_topology_state.drain_intent,
            RuntimeDrainIntent::Draining
        );
        assert_eq!(
            drained_topology_state.drain_phase,
            RuntimeParticipantDrainPhase::TakeoverPending
        );
        assert!(drained_topology_state.takeover_registration_id.is_none());
        assert!(drained_topology_state.takeover_acknowledged_at.is_none());
        assert_eq!(
            drained_topology_state.lease.freshness,
            RuntimeLeaseFreshness::Fresh
        );
        assert!(drained_topology_reconciliation.stale_since.is_none());
        assert!(drained_topology_reconciliation.cleanup_workflow.is_none());
        assert!(drained_edge_directory.resolved_registration_ids.is_empty());
        assert_eq!(drained_edge_directory.registrations.len(), 1);
        assert!(!drained_edge_directory.registrations[0].healthy);
        assert_eq!(
            drained_edge_directory.registrations[0].drain_intent,
            Some(RuntimeDrainIntent::Draining)
        );
        assert_eq!(
            drained_edge_directory.registrations[0].drain_phase,
            Some(RuntimeParticipantDrainPhase::TakeoverPending)
        );
        assert!(
            drained_edge_directory.registrations[0]
                .takeover_registration_id
                .is_none()
        );
        assert!(
            drained_edge_directory.registrations[0]
                .takeover_acknowledged_at
                .is_none()
        );
        assert_eq!(
            drained_edge_directory.registrations[0].lease_freshness,
            Some(RuntimeLeaseFreshness::Fresh)
        );
        let cleanup_workflows = cleanup_workflow_store
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(cleanup_workflows.is_empty());
    }

    #[tokio::test]
    async fn runtime_process_registration_context_fails_readyz_on_topology_publication_error() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let state_dir = state
            .create_dir_all("state")
            .unwrap_or_else(|error| panic!("{error}"));
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("readyz-publication-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: state_dir.display().to_string(),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let publication_plan = publication_plan_for_test(&config);
        let registration_store =
            LeaseRegistrationCollection::open_local(runtime_registration_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store =
            CellDirectoryCollection::open_local(runtime_cell_directory_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cleanup_workflow_store =
            WorkflowCollection::<StaleParticipantCleanupWorkflowState>::open_local(
                runtime_stale_participant_cleanup_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let tombstone_history_store = ParticipantTombstoneHistoryCollection::open(
            runtime_participant_tombstone_history_store_path(&state_dir),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let audit_log = AuditLog::open(runtime_audit_log_path(&state_dir))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let outbox = DurableEventRelay::<PlatformEvent>::open(runtime_outbox_path(&state_dir))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let registry_reconciler =
            runtime_registry_reconciler_for_test(&state_dir, &publication_plan).await;
        let registration = activate_runtime_registration(&registration_store, &publication_plan)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let observed_at = time::OffsetDateTime::now_utc();
        let cell_directory = activate_runtime_cell_directory(
            &cell_directory_store,
            &registration_store,
            &cleanup_workflow_store,
            &registry_reconciler,
            &registration,
            observed_at,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let readyz_handle = RuntimeReadyzHandle::default();
        let context = RuntimeProcessRegistrationContext {
            store: registration_store,
            cell_directory_store,
            service_group_directory_store: CellServiceGroupDirectoryCollection::open_local(
                runtime_service_group_directory_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            cleanup_workflow_store,
            registry_reconciler,
            tombstone_history_store,
            audit_log,
            outbox,
            publication_plan,
            topology_handle: RuntimeTopologyHandle::default(),
            readyz_handle: readyz_handle.clone(),
            current_fencing_token: Arc::new(Mutex::new(registration.fencing_token.clone())),
        };

        corrupt_collection(&runtime_participant_tombstone_history_store_path(
            &state_dir,
        ));
        assert!(
            context
                .tombstone_history_store
                .reload_from_disk()
                .await
                .is_err(),
            "corrupted tombstone history store should fail direct reload"
        );

        let error = context
            .publish(&registration, &cell_directory, observed_at)
            .await
            .expect_err("topology publication should fail when the tombstone store is corrupt");
        assert!(
            error
                .to_string()
                .contains("failed to decode document collection"),
            "unexpected publication failure: {error}"
        );
        let failure = readyz_handle
            .failure()
            .unwrap_or_else(|| panic!("readyz failure should be latched"));
        assert_eq!(
            failure.reason,
            RuntimeReadyzFailureReason::TopologyPublicationFailed
        );
        assert!(
            failure
                .detail
                .contains("failed to decode document collection"),
            "unexpected readyz detail: {}",
            failure.detail
        );
    }

    #[tokio::test]
    async fn runtime_process_registration_context_fails_readyz_on_lease_renewal_error() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let state_dir = state
            .create_dir_all("state")
            .unwrap_or_else(|error| panic!("{error}"));
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("readyz-renewal-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: state_dir.display().to_string(),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let publication_plan = publication_plan_for_test(&config);
        let registration_store =
            LeaseRegistrationCollection::open_local(runtime_registration_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store =
            CellDirectoryCollection::open_local(runtime_cell_directory_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cleanup_workflow_store =
            WorkflowCollection::<StaleParticipantCleanupWorkflowState>::open_local(
                runtime_stale_participant_cleanup_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let tombstone_history_store = ParticipantTombstoneHistoryCollection::open(
            runtime_participant_tombstone_history_store_path(&state_dir),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let audit_log = AuditLog::open(runtime_audit_log_path(&state_dir))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let outbox = DurableEventRelay::<PlatformEvent>::open(runtime_outbox_path(&state_dir))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let registry_reconciler =
            runtime_registry_reconciler_for_test(&state_dir, &publication_plan).await;
        let registration = activate_runtime_registration(&registration_store, &publication_plan)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let observed_at = time::OffsetDateTime::now_utc();
        let cell_directory = activate_runtime_cell_directory(
            &cell_directory_store,
            &registration_store,
            &cleanup_workflow_store,
            &registry_reconciler,
            &registration,
            observed_at,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let readyz_handle = RuntimeReadyzHandle::default();
        let context = RuntimeProcessRegistrationContext {
            store: registration_store,
            cell_directory_store,
            service_group_directory_store: CellServiceGroupDirectoryCollection::open_local(
                runtime_service_group_directory_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            cleanup_workflow_store,
            registry_reconciler,
            tombstone_history_store,
            audit_log,
            outbox,
            publication_plan,
            topology_handle: RuntimeTopologyHandle::default(),
            readyz_handle: readyz_handle.clone(),
            current_fencing_token: Arc::new(Mutex::new(registration.fencing_token.clone())),
        };
        context
            .publish(&registration, &cell_directory, observed_at)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        corrupt_collection(&runtime_registration_store_path(&state_dir));
        let direct_reload = context
            .store
            .local_document_store()
            .unwrap_or_else(|| panic!("registration store should expose a local document store"))
            .reload_from_disk()
            .await;
        assert!(
            direct_reload.is_err(),
            "corrupted registration store should fail direct reload"
        );

        let error = context
            .renew()
            .await
            .expect_err("lease renewal should fail when the registration store is corrupt");
        assert!(
            error
                .to_string()
                .contains("failed to decode document collection"),
            "unexpected renewal failure: {error}"
        );
        let failure = readyz_handle
            .failure()
            .unwrap_or_else(|| panic!("readyz failure should be latched"));
        assert_eq!(
            failure.reason,
            RuntimeReadyzFailureReason::LeaseRenewalFailed
        );
        assert!(
            failure
                .detail
                .contains("failed to decode document collection"),
            "unexpected readyz detail: {}",
            failure.detail
        );
    }

    #[tokio::test]
    async fn runtime_process_registration_context_rejects_renew_with_stale_fence() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let state_dir = state
            .create_dir_all("state")
            .unwrap_or_else(|error| panic!("{error}"));
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("stale-fence-renew-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: state_dir.display().to_string(),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let publication_plan = publication_plan_for_test(&config);
        let registration_store =
            LeaseRegistrationCollection::open_local(runtime_registration_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let registration = activate_runtime_registration(&registration_store, &publication_plan)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let readyz_handle = RuntimeReadyzHandle::default();
        let context = RuntimeProcessRegistrationContext {
            store: registration_store.clone(),
            cell_directory_store: CellDirectoryCollection::open_local(
                runtime_cell_directory_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            service_group_directory_store: CellServiceGroupDirectoryCollection::open_local(
                runtime_service_group_directory_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            cleanup_workflow_store:
                WorkflowCollection::<StaleParticipantCleanupWorkflowState>::open_local(
                    runtime_stale_participant_cleanup_store_path(&state_dir),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
            registry_reconciler: runtime_registry_reconciler_for_test(
                &state_dir,
                &publication_plan,
            )
            .await,
            tombstone_history_store: ParticipantTombstoneHistoryCollection::open(
                runtime_participant_tombstone_history_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            audit_log: AuditLog::open(runtime_audit_log_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}")),
            outbox: DurableEventRelay::<PlatformEvent>::open(runtime_outbox_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}")),
            publication_plan: publication_plan.clone(),
            topology_handle: RuntimeTopologyHandle::default(),
            readyz_handle: readyz_handle.clone(),
            current_fencing_token: Arc::new(Mutex::new(registration.fencing_token.clone())),
        };

        let reclaimed = activate_runtime_registration(&registration_store, &publication_plan)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(reclaimed.incarnation, registration.incarnation + 1);
        assert_ne!(reclaimed.fencing_token, registration.fencing_token);

        let error = context
            .renew()
            .await
            .expect_err("renew should fail when the runtime fence is stale");
        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(
            error
                .to_string()
                .contains("lease fencing token does not match"),
            "unexpected stale-fence renewal error: {error}"
        );

        let failure = readyz_handle
            .failure()
            .unwrap_or_else(|| panic!("readyz failure should be latched"));
        assert_eq!(
            failure.reason,
            RuntimeReadyzFailureReason::LeaseRenewalFailed
        );
        assert!(
            failure
                .detail
                .contains("lease fencing token does not match"),
            "unexpected readyz detail: {}",
            failure.detail
        );

        let stored = registration_store
            .get(publication_plan.registration_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reclaimed registration"));
        assert_eq!(stored.value.incarnation, reclaimed.incarnation);
        assert_eq!(stored.value.fencing_token, reclaimed.fencing_token);
        assert_eq!(stored.value.drain_intent, LeaseDrainIntent::Serving);
    }

    #[tokio::test]
    async fn runtime_process_registration_context_rejects_drain_with_stale_fence() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let state_dir = state
            .create_dir_all("state")
            .unwrap_or_else(|error| panic!("{error}"));
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("stale-fence-drain-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: state_dir.display().to_string(),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let publication_plan = publication_plan_for_test(&config);
        let registration_store =
            LeaseRegistrationCollection::open_local(runtime_registration_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let registration = activate_runtime_registration(&registration_store, &publication_plan)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RuntimeProcessRegistrationContext {
            store: registration_store.clone(),
            cell_directory_store: CellDirectoryCollection::open_local(
                runtime_cell_directory_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            service_group_directory_store: CellServiceGroupDirectoryCollection::open_local(
                runtime_service_group_directory_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            cleanup_workflow_store:
                WorkflowCollection::<StaleParticipantCleanupWorkflowState>::open_local(
                    runtime_stale_participant_cleanup_store_path(&state_dir),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
            registry_reconciler: runtime_registry_reconciler_for_test(
                &state_dir,
                &publication_plan,
            )
            .await,
            tombstone_history_store: ParticipantTombstoneHistoryCollection::open(
                runtime_participant_tombstone_history_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            audit_log: AuditLog::open(runtime_audit_log_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}")),
            outbox: DurableEventRelay::<PlatformEvent>::open(runtime_outbox_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}")),
            publication_plan: publication_plan.clone(),
            topology_handle: RuntimeTopologyHandle::default(),
            readyz_handle: RuntimeReadyzHandle::default(),
            current_fencing_token: Arc::new(Mutex::new(registration.fencing_token.clone())),
        };

        let reclaimed = activate_runtime_registration(&registration_store, &publication_plan)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(reclaimed.incarnation, registration.incarnation + 1);
        assert_ne!(reclaimed.fencing_token, registration.fencing_token);

        let error = context
            .request_drain()
            .await
            .expect_err("drain should fail when the runtime fence is stale");
        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(
            error
                .to_string()
                .contains("lease fencing token does not match"),
            "unexpected stale-fence drain error: {error}"
        );

        let stored = registration_store
            .get(publication_plan.registration_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reclaimed registration"));
        assert_eq!(stored.value.incarnation, reclaimed.incarnation);
        assert_eq!(stored.value.fencing_token, reclaimed.fencing_token);
        assert_eq!(stored.value.drain_intent, LeaseDrainIntent::Serving);
    }

    #[tokio::test]
    async fn runtime_process_registration_context_reclaims_deleted_registration_and_drains_with_rotated_fence()
     {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let state_dir = state
            .create_dir_all("state")
            .unwrap_or_else(|error| panic!("{error}"));
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::AllInOne,
                node_name: String::from("deleted-registration-reclaim-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: state_dir.display().to_string(),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig::default(),
        };

        let publication_plan = publication_plan_for_test(&config);
        let placement = config
            .runtime_cell_placement()
            .unwrap_or_else(|error| panic!("{error}"));
        let registration_store =
            LeaseRegistrationCollection::open_local(runtime_registration_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store =
            CellDirectoryCollection::open_local(runtime_cell_directory_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cleanup_workflow_store =
            WorkflowCollection::<StaleParticipantCleanupWorkflowState>::open_local(
                runtime_stale_participant_cleanup_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let tombstone_history_store = ParticipantTombstoneHistoryCollection::open(
            runtime_participant_tombstone_history_store_path(&state_dir),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let audit_log = AuditLog::open(runtime_audit_log_path(&state_dir))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let outbox = DurableEventRelay::<PlatformEvent>::open(runtime_outbox_path(&state_dir))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let registry_reconciler =
            runtime_registry_reconciler_for_test(&state_dir, &publication_plan).await;
        let service_group_directory_store = CellServiceGroupDirectoryCollection::open_local(
            runtime_service_group_directory_store_path(&state_dir),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let initial_registration =
            activate_runtime_registration(&registration_store, &publication_plan)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let initial_fencing_token = initial_registration.fencing_token.clone();
        let initial_observed_at = time::OffsetDateTime::now_utc();
        let initial_cell_directory = activate_runtime_cell_directory(
            &cell_directory_store,
            &registration_store,
            &cleanup_workflow_store,
            &registry_reconciler,
            &initial_registration,
            initial_observed_at,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let topology_handle = RuntimeTopologyHandle::default();
        let context = RuntimeProcessRegistrationContext {
            store: registration_store.clone(),
            cell_directory_store: cell_directory_store.clone(),
            service_group_directory_store,
            cleanup_workflow_store,
            registry_reconciler,
            tombstone_history_store,
            audit_log,
            outbox,
            publication_plan: publication_plan.clone(),
            topology_handle: topology_handle.clone(),
            readyz_handle: RuntimeReadyzHandle::default(),
            current_fencing_token: Arc::new(Mutex::new(initial_fencing_token.clone())),
        };
        context
            .publish(
                &initial_registration,
                &initial_cell_directory,
                initial_observed_at,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let initial_stored = registration_store
            .get(publication_plan.registration_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing initial runtime registration"));
        registration_store
            .soft_delete(
                publication_plan.registration_key(),
                Some(initial_stored.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        context
            .renew()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reclaimed = registration_store
            .get(publication_plan.registration_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reclaimed runtime registration"));
        assert!(!reclaimed.deleted);
        assert_eq!(
            reclaimed.value.incarnation,
            initial_registration.incarnation + 1
        );
        assert_ne!(reclaimed.value.fencing_token, initial_fencing_token);
        assert_eq!(
            context.current_fencing_token(),
            reclaimed.value.fencing_token
        );
        assert_eq!(reclaimed.value.readiness, LeaseReadiness::Ready);
        assert_eq!(reclaimed.value.drain_intent, LeaseDrainIntent::Serving);

        context
            .request_drain()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let drained = registration_store
            .get(publication_plan.registration_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing drained runtime registration"));
        assert!(!drained.deleted);
        assert_eq!(drained.value.incarnation, reclaimed.value.incarnation);
        assert_eq!(drained.value.fencing_token, reclaimed.value.fencing_token);
        assert_eq!(drained.value.readiness, LeaseReadiness::Ready);
        assert_eq!(drained.value.drain_intent, LeaseDrainIntent::Draining);
        assert_eq!(context.current_fencing_token(), drained.value.fencing_token);

        let drained_directory = cell_directory_store
            .get(placement.cell_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing drained cell directory"));
        let drained_participant = drained_directory
            .value
            .participants
            .iter()
            .find(|participant| participant.registration_id == publication_plan.registration_key())
            .unwrap_or_else(|| panic!("missing drained participant"));
        let drained_participant_state = drained_participant
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing drained participant state"));
        assert_eq!(drained_participant_state.readiness, LeaseReadiness::Ready);
        assert_eq!(
            drained_participant_state.drain_intent,
            LeaseDrainIntent::Draining
        );
        assert_eq!(
            drained_participant_state.drain_phase,
            CellParticipantDrainPhase::TakeoverPending
        );

        let drained_process_state = topology_handle
            .snapshot()
            .process_state
            .unwrap_or_else(|| panic!("missing drained process state"));
        assert_eq!(
            drained_process_state.readiness,
            RuntimeReadinessState::Ready
        );
        assert_eq!(
            drained_process_state.drain_intent,
            RuntimeDrainIntent::Draining
        );
    }

    #[tokio::test]
    async fn runtime_cell_directory_activation_reconciles_new_peer_from_replayed_registry_state() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let state_dir = state
            .create_dir_all("state")
            .unwrap_or_else(|error| panic!("{error}"));
        let config = AllInOneConfig {
            schema: ConfigSchema {
                schema_version: 1,
                mode: ServiceMode::Distributed,
                node_name: String::from("controller-registry-test-node"),
            },
            listen: String::from("127.0.0.1:9080"),
            state_dir: state_dir.display().to_string(),
            secrets: SecretsConfig {
                master_key: Some(development_master_key()),
            },
            security: SecurityConfig {
                bootstrap_admin_token: None,
            },
            placement: PlacementConfig::default(),
            runtime: RuntimeConfig {
                process_role: Some(RuntimeProcessRole::Controller.as_str().to_owned()),
                forward_targets: BTreeMap::new(),
            },
        };

        let publication_plan = publication_plan_for_test(&config);
        assert!(publication_plan.owns_runtime_registry_reconciliation());
        let placement = config
            .runtime_cell_placement()
            .unwrap_or_else(|error| panic!("{error}"));
        let registration_store =
            LeaseRegistrationCollection::open_local(runtime_registration_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store =
            CellDirectoryCollection::open_local(runtime_cell_directory_store_path(&state_dir))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let cleanup_workflow_store =
            WorkflowCollection::<StaleParticipantCleanupWorkflowState>::open_local(
                runtime_stale_participant_cleanup_store_path(&state_dir),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let registry_reconciler =
            runtime_registry_reconciler_for_test(&state_dir, &publication_plan).await;
        let reconciler_state_store = MetadataCollection::<LocalCellRegistryState>::open_local(
            runtime_registry_reconciler_store_path(&state_dir),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let registration = activate_runtime_registration(&registration_store, &publication_plan)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let peer_publication_plan = runtime_role_activation_plan(RuntimeProcessRole::Worker)
            .publication_plan(
                config.schema.mode,
                String::from("replayed-peer-node"),
                placement.region_membership(),
                placement.cell_membership(),
            );
        let peer_key = peer_publication_plan.registration_key().to_owned();
        let _peer_registration =
            activate_runtime_registration(&registration_store, &peer_publication_plan)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let peer_registration = mutate_runtime_registration(
            &registration_store,
            peer_key.as_str(),
            |peer_registration| {
                peer_registration.set_drain_intent(LeaseDrainIntent::Draining);
                peer_registration.expire_now();
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_or_else(|| panic!("missing peer registration"));

        let observed_at = time::OffsetDateTime::now_utc();
        let initial_directory = activate_runtime_cell_directory(
            &cell_directory_store,
            &registration_store,
            &cleanup_workflow_store,
            &registry_reconciler,
            &registration,
            observed_at,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(initial_directory.participants.len(), 1);

        let persisted_state = reconciler_state_store
            .get(placement.cell_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted registry reconciler state"));
        assert!(persisted_state.value.lease_cursor.revision > 0);
        assert_eq!(
            persisted_state
                .value
                .active_registrations
                .get(peer_key.as_str()),
            Some(&peer_registration)
        );

        let current_directory = cell_directory_store
            .get(placement.cell_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing current cell directory"));
        let mut seeded_directory = current_directory.value.clone();
        let mut seeded_peer = CellParticipantRecord::new(
            peer_key.clone(),
            RUNTIME_PROCESS_SUBJECT_KIND,
            peer_key.clone(),
            RuntimeProcessRole::Worker.as_str(),
        )
        .with_node_name("replayed-peer-node")
        .with_service_groups(["data_and_messaging"])
        .with_lease_registration_id(peer_key.clone())
        .with_state(CellParticipantState::new(
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            CellParticipantLeaseState::new(
                observed_at - time::Duration::seconds(5),
                observed_at + time::Duration::seconds(30),
                RUNTIME_PROCESS_LEASE_DURATION_SECONDS,
                LeaseFreshness::Fresh,
            ),
        ))
        .with_reconciliation(CellParticipantReconciliationState::new(
            observed_at - time::Duration::seconds(10),
        ));
        seeded_peer.registered_at = peer_registration.registered_at;
        seeded_directory.upsert_participant(seeded_peer);
        cell_directory_store
            .upsert(
                placement.cell_id.as_str(),
                seeded_directory,
                Some(current_directory.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let replay_observed_at = observed_at + time::Duration::seconds(5);
        let reconciled_directory = activate_runtime_cell_directory(
            &cell_directory_store,
            &registration_store,
            &cleanup_workflow_store,
            &registry_reconciler,
            &registration,
            replay_observed_at,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let reconciled_peer = reconciled_directory
            .participants
            .iter()
            .find(|participant| participant.registration_id == peer_key)
            .unwrap_or_else(|| panic!("missing reconciled peer participant"));
        let reconciled_peer_state = reconciled_peer
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing reconciled peer state"));
        assert_eq!(reconciled_peer_state.readiness, LeaseReadiness::Ready);
        assert_eq!(
            reconciled_peer_state.drain_intent,
            LeaseDrainIntent::Draining
        );
        assert_eq!(
            reconciled_peer_state.lease.freshness,
            LeaseFreshness::Expired
        );
        assert_eq!(
            reconciled_peer_state.lease_source,
            CellParticipantLeaseSource::LinkedRegistration
        );

        let replayed_state = reconciler_state_store
            .get(placement.cell_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing replayed registry reconciler state"));
        assert!(
            replayed_state.value.cell_directory_cursor.revision
                > persisted_state.value.cell_directory_cursor.revision
        );
    }

    #[test]
    fn route_surface_manifest_is_reflected_in_openapi_contract() {
        let openapi = fs::read_to_string(workspace_root().join("openapi/control-plane-v1.yaml"))
            .unwrap_or_else(|error| panic!("failed to read OpenAPI contract: {error}"));

        for binding in uhost_runtime::reserved_route_surfaces().iter().copied() {
            let block = route_surface_contract_block("runtime", binding);
            assert!(
                openapi.contains(&block),
                "OpenAPI route surface manifest missing runtime block:\n{block}"
            );
        }

        for manifest in SERVICE_ROUTE_SURFACE_MANIFESTS {
            for binding in manifest.route_surfaces.iter().copied() {
                let block = route_surface_contract_block(manifest.service_name(), binding);
                assert!(
                    openapi.contains(&block),
                    "OpenAPI route surface manifest missing service block:\n{block}"
                );
            }
        }
    }
}
