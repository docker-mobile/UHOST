//! Node agent intake service.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use http::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{PlatformError, RequestContext, Result, canonicalize_hostname, sha256_hex};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{AuditLog, DocumentStore, DurableOutbox, OutboxMessage};
use uhost_types::{
    AuditActor, AuditId, EventHeader, EventPayload, NodeId, OwnershipScope, PlatformEvent,
    ResourceMetadata, ServiceEvent, UvmRuntimeSessionId, WorkloadId,
};

/// Heartbeat status from a node agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeHeartbeat {
    pub node_id: NodeId,
    pub hostname: String,
    pub healthy: bool,
    pub agent_version: String,
    pub cache_bytes: u64,
    pub last_seen: OffsetDateTime,
    pub metadata: ResourceMetadata,
}

/// Process report from a node agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessReport {
    pub node_id: NodeId,
    pub workload_id: WorkloadId,
    pub state: String,
    pub exit_code: Option<i32>,
    pub updated_at: OffsetDateTime,
}

const HEARTBEAT_STALE_THRESHOLD: Duration = Duration::minutes(5);
const UVM_SYNTHETIC_AGENT_VERSION: &str = "uvm-node-supervision.v1";

#[derive(Debug, Serialize)]
struct NodeSummary {
    state_root: String,
    heartbeats: HeartbeatSummary,
    process_reports: ProcessReportSummary,
    outbox: OutboxSummary,
}

#[derive(Debug, Serialize)]
struct HeartbeatSummary {
    total: u64,
    healthy: u64,
    degraded: u64,
    stale: u64,
    unique_nodes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize)]
struct ProcessReportSummary {
    total: u64,
    states: HashMap<String, u64>,
}

#[derive(Debug, Serialize)]
struct OutboxSummary {
    pending_messages: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HeartbeatRequest {
    node_id: String,
    hostname: String,
    healthy: bool,
    agent_version: String,
    cache_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProcessReportRequest {
    node_id: String,
    workload_id: String,
    state: String,
    exit_code: Option<i32>,
}

mod uvm_state {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct RuntimeSessionRecord {
        pub id: UvmRuntimeSessionId,
        pub node_id: NodeId,
        pub state: String,
        pub last_heartbeat_at: Option<OffsetDateTime>,
        pub last_transition_at: OffsetDateTime,
        pub hypervisor_health: String,
        #[serde(default, flatten)]
        pub extra_fields: BTreeMap<String, Value>,
    }
}

#[derive(Debug, Clone)]
struct UvmNodeHeartbeatAggregate {
    node_id: NodeId,
    last_seen: OffsetDateTime,
    healthy: bool,
}

impl UvmNodeHeartbeatAggregate {
    fn into_heartbeat(self) -> NodeHeartbeat {
        NodeHeartbeat {
            node_id: self.node_id.clone(),
            hostname: synthetic_uvm_hostname(&self.node_id),
            healthy: self.healthy,
            agent_version: String::from(UVM_SYNTHETIC_AGENT_VERSION),
            cache_bytes: 0,
            last_seen: self.last_seen,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(self.node_id.to_string()),
                sha256_hex(self.node_id.as_str().as_bytes()),
            ),
        }
    }
}

/// Node service.
#[derive(Debug, Clone)]
pub struct NodeService {
    heartbeats: DocumentStore<NodeHeartbeat>,
    reports: DocumentStore<ProcessReport>,
    uvm_runtime_sessions: DocumentStore<uvm_state::RuntimeSessionRecord>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    state_root: PathBuf,
}

impl NodeService {
    /// Open node service state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let platform_root = state_root.as_ref();
        let root = platform_root.join("node");
        Ok(Self {
            heartbeats: DocumentStore::open(root.join("heartbeats.json")).await?,
            reports: DocumentStore::open(root.join("process_reports.json")).await?,
            uvm_runtime_sessions: DocumentStore::open(
                platform_root.join("uvm-node/runtime_sessions.json"),
            )
            .await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            state_root: root,
        })
    }

    async fn record_heartbeat(
        &self,
        request: HeartbeatRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let node_id = NodeId::parse(request.node_id).map_err(|error| {
            PlatformError::invalid("invalid node_id").with_detail(error.to_string())
        })?;
        let hostname = canonicalize_hostname(request.hostname.trim())?;
        let agent_version = normalize_required_field("agent_version", &request.agent_version)?;
        let heartbeat = NodeHeartbeat {
            node_id: node_id.clone(),
            hostname,
            healthy: request.healthy,
            agent_version,
            cache_bytes: request.cache_bytes,
            last_seen: OffsetDateTime::now_utc(),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(node_id.to_string()),
                sha256_hex(node_id.as_str().as_bytes()),
            ),
        };
        let stored = self
            .heartbeats
            .upsert(node_id.as_str(), heartbeat, None)
            .await?;
        self.emit_service_event(
            "node.heartbeat.recorded.v1",
            "node_heartbeat",
            node_id.as_str(),
            "recorded",
            json!({
                "node_id": node_id.as_str(),
                "hostname": &stored.value.hostname,
                "healthy": stored.value.healthy,
                "agent_version": &stored.value.agent_version,
                "cache_bytes": stored.value.cache_bytes,
                "last_seen": &stored.value.last_seen,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &stored.value)
    }

    async fn record_process_report(
        &self,
        request: ProcessReportRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let node_id = NodeId::parse(request.node_id).map_err(|error| {
            PlatformError::invalid("invalid node_id").with_detail(error.to_string())
        })?;
        let workload_id = WorkloadId::parse(request.workload_id).map_err(|error| {
            PlatformError::invalid("invalid workload_id").with_detail(error.to_string())
        })?;
        let state = normalize_required_field("state", &request.state)?;
        let report = ProcessReport {
            node_id,
            workload_id: workload_id.clone(),
            state,
            exit_code: request.exit_code,
            updated_at: OffsetDateTime::now_utc(),
        };
        let stored = self
            .reports
            .upsert(workload_id.as_str(), report, None)
            .await?;
        self.emit_service_event(
            "node.process_report.recorded.v1",
            "process_report",
            workload_id.as_str(),
            "recorded",
            json!({
                "node_id": stored.value.node_id.as_str(),
                "workload_id": stored.value.workload_id.as_str(),
                "state": &stored.value.state,
                "exit_code": stored.value.exit_code,
                "updated_at": &stored.value.updated_at,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &stored.value)
    }

    async fn emit_service_event(
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
                source_service: String::from("node"),
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
            .enqueue("node.events.v1", event, Some(&idempotency))
            .await?;
        Ok(())
    }

    async fn merged_heartbeats(&self) -> Result<Vec<NodeHeartbeat>> {
        let mut merged = self
            .heartbeats
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| (stored.value.node_id.clone(), stored.value))
            .collect::<HashMap<_, _>>();
        for aggregate in self.uvm_heartbeat_aggregates().await? {
            merged
                .entry(aggregate.node_id.clone())
                .and_modify(|heartbeat| {
                    heartbeat.healthy = heartbeat.healthy && aggregate.healthy;
                    if aggregate.last_seen > heartbeat.last_seen {
                        heartbeat.last_seen = aggregate.last_seen;
                    }
                })
                .or_insert_with(|| aggregate.into_heartbeat());
        }
        Ok(merged.into_values().collect())
    }

    async fn uvm_heartbeat_aggregates(&self) -> Result<Vec<UvmNodeHeartbeatAggregate>> {
        let mut aggregates = HashMap::<NodeId, UvmNodeHeartbeatAggregate>::new();
        for (_, stored) in self.uvm_runtime_sessions.list().await? {
            if stored.deleted {
                continue;
            }
            let runtime = stored.value;
            if !runtime_state_has_liveness(&runtime.state) {
                continue;
            }
            let observed_at = runtime
                .last_heartbeat_at
                .unwrap_or(runtime.last_transition_at);
            let healthy = runtime_state_is_healthy(&runtime);
            let entry =
                aggregates
                    .entry(runtime.node_id.clone())
                    .or_insert(UvmNodeHeartbeatAggregate {
                        node_id: runtime.node_id.clone(),
                        last_seen: observed_at,
                        healthy,
                    });
            if observed_at > entry.last_seen {
                entry.last_seen = observed_at;
            }
            entry.healthy &= healthy;
        }
        Ok(aggregates.into_values().collect())
    }

    async fn merged_process_reports(&self) -> Result<Vec<ProcessReport>> {
        let mut merged = self
            .reports
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| (stored.value.workload_id.clone(), stored.value))
            .collect::<HashMap<_, _>>();
        for (_, stored) in self.uvm_runtime_sessions.list().await? {
            if stored.deleted {
                continue;
            }
            let report = runtime_process_report(&stored.value)?;
            let key = report.workload_id.clone();
            match merged.get(&key) {
                Some(existing) if existing.updated_at > report.updated_at => {}
                _ => {
                    merged.insert(key, report);
                }
            }
        }
        Ok(merged.into_values().collect())
    }

    async fn node_summary(&self) -> Result<NodeSummary> {
        let now = OffsetDateTime::now_utc();
        let heartbeats = self.merged_heartbeats().await?;
        let mut healthy = 0;
        let mut degraded = 0;
        let mut stale = 0;
        let mut unique_nodes = HashSet::new();
        let mut last_seen = None;
        for heartbeat in &heartbeats {
            unique_nodes.insert(heartbeat.node_id.clone());
            if last_seen
                .as_ref()
                .is_none_or(|current| heartbeat.last_seen > *current)
            {
                last_seen = Some(heartbeat.last_seen);
            }
            let age = if heartbeat.last_seen > now {
                Duration::ZERO
            } else {
                now - heartbeat.last_seen
            };
            if age > HEARTBEAT_STALE_THRESHOLD {
                stale += 1;
            } else if heartbeat.healthy {
                healthy += 1;
            } else {
                degraded += 1;
            }
        }
        let heartbeat_summary = HeartbeatSummary {
            total: heartbeats.len() as u64,
            healthy,
            degraded,
            stale,
            unique_nodes: unique_nodes.len() as u64,
            last_seen,
        };

        let process_reports = self.merged_process_reports().await?;
        let mut states = HashMap::new();
        for report in &process_reports {
            *states.entry(report.state.clone()).or_insert(0) += 1;
        }
        let process_summary = ProcessReportSummary {
            total: process_reports.len() as u64,
            states,
        };

        let pending_messages = self.list_outbox_messages().await?;
        let outbox_summary = OutboxSummary {
            pending_messages: pending_messages.len() as u64,
        };

        Ok(NodeSummary {
            state_root: self.state_root.display().to_string(),
            heartbeats: heartbeat_summary,
            process_reports: process_summary,
            outbox: outbox_summary,
        })
    }

    pub async fn list_outbox_messages(&self) -> Result<Vec<OutboxMessage<PlatformEvent>>> {
        self.outbox.list_all().await
    }
}

impl HttpService for NodeService {
    fn name(&self) -> &'static str {
        "node"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/node")];
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
                (Method::GET, ["node"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                    }),
                )
                .map(Some),
                (Method::GET, ["node", "summary"]) => {
                    let summary = self.node_summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["node", "heartbeats"]) => {
                    let heartbeats = self.merged_heartbeats().await?;
                    json_response(StatusCode::OK, &heartbeats).map(Some)
                }
                (Method::POST, ["node", "heartbeats"]) => {
                    let body: HeartbeatRequest = parse_json(request).await?;
                    self.record_heartbeat(body, &context).await.map(Some)
                }
                (Method::GET, ["node", "process-reports"]) => {
                    let reports = self.merged_process_reports().await?;
                    json_response(StatusCode::OK, &reports).map(Some)
                }
                (Method::GET, ["node", "outbox"]) => {
                    let messages = self.list_outbox_messages().await?;
                    json_response(StatusCode::OK, &messages).map(Some)
                }
                (Method::POST, ["node", "process-reports"]) => {
                    let body: ProcessReportRequest = parse_json(request).await?;
                    self.record_process_report(body, &context).await.map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn normalize_required_field(field: &'static str, value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(format!("{field} must not be empty")));
    }

    Ok(trimmed.to_owned())
}

fn synthetic_uvm_hostname(node_id: &NodeId) -> String {
    let suffix = node_id
        .as_str()
        .split_once('_')
        .map_or(node_id.as_str(), |(_, body)| body);
    format!("uvm-node-{suffix}.local")
}

fn runtime_state_has_liveness(state: &str) -> bool {
    matches!(state, "running" | "recovering")
}

fn runtime_state_is_healthy(runtime: &uvm_state::RuntimeSessionRecord) -> bool {
    runtime.state == "running"
        && !matches!(runtime.hypervisor_health.as_str(), "degraded" | "failed")
}

fn runtime_process_report(runtime: &uvm_state::RuntimeSessionRecord) -> Result<ProcessReport> {
    Ok(ProcessReport {
        node_id: runtime.node_id.clone(),
        workload_id: workload_id_from_runtime_session(&runtime.id)?,
        state: runtime.state.clone(),
        exit_code: match runtime.state.as_str() {
            "failed" => Some(1),
            "stopped" => Some(0),
            _ => None,
        },
        updated_at: runtime
            .last_heartbeat_at
            .unwrap_or(runtime.last_transition_at),
    })
}

fn workload_id_from_runtime_session(
    runtime_session_id: &UvmRuntimeSessionId,
) -> Result<WorkloadId> {
    let (_, body) = runtime_session_id
        .as_str()
        .split_once('_')
        .ok_or_else(|| PlatformError::invalid("runtime session id missing prefix separator"))?;
    WorkloadId::parse(format!("wrk_{body}")).map_err(|error| {
        PlatformError::invalid("failed to synthesize workload id from runtime session")
            .with_detail(error.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use http_body_util::BodyExt;
    use tempfile::tempdir;
    use time::{Duration, OffsetDateTime};

    async fn read_json<T: serde::de::DeserializeOwned>(response: http::Response<ApiBody>) -> T {
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"))
    }

    #[tokio::test]
    async fn heartbeat_normalizes_hostname_and_version() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .record_heartbeat(
                HeartbeatRequest {
                    node_id: String::from("nod_aaaaaaaaaaaaaaaaaaaa"),
                    hostname: String::from("  NODE-1.Example.COM. "),
                    healthy: true,
                    agent_version: String::from("  1.2.3  "),
                    cache_bytes: 42,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let heartbeat: NodeHeartbeat = read_json(response).await;
        assert_eq!(heartbeat.hostname, "node-1.example.com");
        assert_eq!(heartbeat.agent_version, "1.2.3");
    }

    #[tokio::test]
    async fn heartbeat_rejects_blank_hostname_or_version() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .record_heartbeat(
                HeartbeatRequest {
                    node_id: String::from("nod_aaaaaaaaaaaaaaaaaaaa"),
                    hostname: String::from("   "),
                    healthy: true,
                    agent_version: String::from("1.2.3"),
                    cache_bytes: 42,
                },
                &context,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);

        let error = service
            .record_heartbeat(
                HeartbeatRequest {
                    node_id: String::from("nod_aaaaaaaaaaaaaaaaaaaa"),
                    hostname: String::from("node-1.example.com"),
                    healthy: true,
                    agent_version: String::from("\n\t"),
                    cache_bytes: 42,
                },
                &context,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn process_report_trims_state_and_rejects_blank_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .record_process_report(
                ProcessReportRequest {
                    node_id: String::from("nod_aaaaaaaaaaaaaaaaaaaa"),
                    workload_id: String::from("wrk_aaaaaaaaaaaaaaaaaaaa"),
                    state: String::from("  exited  "),
                    exit_code: Some(0),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let report: ProcessReport = read_json(response).await;
        assert_eq!(report.state, "exited");

        let error = service
            .record_process_report(
                ProcessReportRequest {
                    node_id: String::from("nod_aaaaaaaaaaaaaaaaaaaa"),
                    workload_id: String::from("wrk_aaaaaaaaaaaaaaaaaaaa"),
                    state: String::from(" \r\n "),
                    exit_code: None,
                },
                &context,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn heartbeat_emits_platform_event() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        service
            .record_heartbeat(
                HeartbeatRequest {
                    node_id: String::from("nod_aaaaaaaaaaaaaaaaaaaa"),
                    hostname: String::from("node-1.example.com"),
                    healthy: true,
                    agent_version: String::from("1.2.3"),
                    cache_bytes: 1,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let messages = service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(messages.len(), 1);
        let message = &messages[0];
        assert_eq!(message.topic, "node.events.v1");
        assert_eq!(message.payload.header.source_service, "node");
        assert_eq!(message.payload.header.actor.subject, "system");
        if let EventPayload::Service(event) = &message.payload.payload {
            assert_eq!(event.resource_kind, "node_heartbeat");
            assert_eq!(event.resource_id, "nod_aaaaaaaaaaaaaaaaaaaa");
            assert_eq!(event.action, "recorded");
        } else {
            panic!("expected service payload");
        }
    }

    #[tokio::test]
    async fn process_report_emits_platform_event() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        service
            .record_process_report(
                ProcessReportRequest {
                    node_id: String::from("nod_aaaaaaaaaaaaaaaaaaaa"),
                    workload_id: String::from("wrk_aaaaaaaaaaaaaaaaaaaa"),
                    state: String::from("exited"),
                    exit_code: Some(0),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let messages = service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(messages.len(), 1);
        let message = &messages[0];
        if let EventPayload::Service(event) = &message.payload.payload {
            assert_eq!(event.resource_kind, "process_report");
            assert_eq!(event.resource_id, "wrk_aaaaaaaaaaaaaaaaaaaa");
            assert_eq!(event.action, "recorded");
            assert_eq!(
                event.details.get("state"),
                Some(&serde_json::json!("exited"))
            );
        } else {
            panic!("expected service payload");
        }
    }

    #[tokio::test]
    async fn node_summary_reflects_persisted_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .record_heartbeat(
                HeartbeatRequest {
                    node_id: String::from("nod_aaaaaaaaaaaaaaaaaaaa"),
                    hostname: String::from("node-1.example.com"),
                    healthy: true,
                    agent_version: String::from("1.2.3"),
                    cache_bytes: 12,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .record_heartbeat(
                HeartbeatRequest {
                    node_id: String::from("nod_bbbbbbbbbbbbbbbbbbbb"),
                    hostname: String::from("node-2.example.com"),
                    healthy: false,
                    agent_version: String::from("1.2.4"),
                    cache_bytes: 16,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .record_process_report(
                ProcessReportRequest {
                    node_id: String::from("nod_aaaaaaaaaaaaaaaaaaaa"),
                    workload_id: String::from("wrk_aaaaaaaaaaaaaaaaaaaa"),
                    state: String::from("running"),
                    exit_code: Some(0),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .record_process_report(
                ProcessReportRequest {
                    node_id: String::from("nod_bbbbbbbbbbbbbbbbbbbb"),
                    workload_id: String::from("wrk_bbbbbbbbbbbbbbbbbbbb"),
                    state: String::from("failed"),
                    exit_code: Some(1),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stale_node_id =
            NodeId::parse("nod_cccccccccccccccccccc").unwrap_or_else(|error| panic!("{error}"));
        let stale_heartbeat = NodeHeartbeat {
            node_id: stale_node_id.clone(),
            hostname: String::from("node-3.example.com"),
            healthy: true,
            agent_version: String::from("1.2.5"),
            cache_bytes: 0,
            last_seen: OffsetDateTime::now_utc() - Duration::minutes(10),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(stale_node_id.to_string()),
                sha256_hex(stale_node_id.as_str().as_bytes()),
            ),
        };
        service
            .heartbeats
            .upsert(stale_node_id.as_str(), stale_heartbeat, None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .node_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.state_root, service.state_root.display().to_string());
        assert_eq!(summary.heartbeats.total, 3);
        assert_eq!(summary.heartbeats.healthy, 1);
        assert_eq!(summary.heartbeats.degraded, 1);
        assert_eq!(summary.heartbeats.stale, 1);
        assert_eq!(summary.heartbeats.unique_nodes, 3);
        assert!(summary.heartbeats.last_seen.is_some());
        assert_eq!(summary.process_reports.total, 2);
        assert_eq!(summary.process_reports.states.get("running"), Some(&1_u64));
        assert_eq!(summary.process_reports.states.get("failed"), Some(&1_u64));
        assert_eq!(summary.outbox.pending_messages, 4);
    }

    #[tokio::test]
    async fn node_views_merge_uvm_runtime_liveness_and_process_reports() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NodeService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let node_id = NodeId::parse(String::from("nod_aaaaaaaaaaaaaaaaaaaa"))
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime_session_id =
            UvmRuntimeSessionId::parse(String::from("urs_aaaaaaaaaaaaaaaaaaaa"))
                .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .record_heartbeat(
                HeartbeatRequest {
                    node_id: node_id.to_string(),
                    hostname: String::from("node-a"),
                    healthy: true,
                    agent_version: String::from("0.1"),
                    cache_bytes: 128,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let now = OffsetDateTime::now_utc();
        let _ = service
            .uvm_runtime_sessions
            .create(
                runtime_session_id.as_str(),
                uvm_state::RuntimeSessionRecord {
                    id: runtime_session_id.clone(),
                    node_id: node_id.clone(),
                    state: String::from("running"),
                    last_heartbeat_at: Some(now),
                    last_transition_at: now - Duration::seconds(30),
                    hypervisor_health: String::from("failed"),
                    extra_fields: BTreeMap::new(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let heartbeats = service
            .merged_heartbeats()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(heartbeats.len(), 1);
        let heartbeat = heartbeats
            .first()
            .unwrap_or_else(|| panic!("missing merged heartbeat"));
        assert_eq!(heartbeat.node_id, node_id);
        assert_eq!(heartbeat.hostname, "node-a");
        assert_eq!(heartbeat.agent_version, "0.1");
        assert!(!heartbeat.healthy);
        assert!(heartbeat.last_seen >= now);

        let reports = service
            .merged_process_reports()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(reports.len(), 1);
        let report = reports
            .first()
            .unwrap_or_else(|| panic!("missing merged process report"));
        assert_eq!(report.node_id, node_id);
        assert_eq!(
            report.workload_id,
            WorkloadId::parse(String::from("wrk_aaaaaaaaaaaaaaaaaaaa"))
                .unwrap_or_else(|error| panic!("{error}"))
        );
        assert_eq!(report.state, "running");
        assert!(report.exit_code.is_none());

        let summary = service
            .node_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.heartbeats.total, 1);
        assert_eq!(summary.heartbeats.healthy, 0);
        assert_eq!(summary.heartbeats.degraded, 1);
        assert_eq!(summary.process_reports.total, 1);
        assert_eq!(summary.process_reports.states.get("running"), Some(&1_u64));
    }
}
