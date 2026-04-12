//! Scheduler and placement service.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use http::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::fs::{self, OpenOptions};
use tokio::sync::Mutex;
use tokio::time::{Instant, sleep};
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{ErrorCode, PlatformError, RequestContext, Result, sha256_hex};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::DocumentStore;
use uhost_types::{NodeId, OwnershipScope, ResourceMetadata};

const DEFAULT_SCHEDULER_POOL: &str = "general";

/// Node inventory record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInventory {
    pub id: NodeId,
    pub region: String,
    #[serde(default = "default_scheduler_pool")]
    pub scheduler_pool: String,
    pub cpu_millis: u32,
    pub memory_mb: u64,
    pub free_cpu_millis: u32,
    pub free_memory_mb: u64,
    pub drained: bool,
    pub metadata: ResourceMetadata,
}

/// Placement request accepted by the scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PlacementRequest {
    workload_id: String,
    cpu_millis: u32,
    memory_mb: u64,
    region: Option<String>,
    #[serde(default)]
    scheduler_pool: Option<String>,
}

/// Pure demand shape used by scoring and benchmarks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementDemand {
    /// Requested CPU in millicores.
    pub cpu_millis: u32,
    /// Requested memory in MiB.
    pub memory_mb: u64,
}

/// Placement decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlacementDecision {
    pub workload_id: String,
    pub node_id: Option<NodeId>,
    pub score: f64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementDecisionCounts {
    pub total: usize,
    pub placed: usize,
    pub unplaced: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerSummary {
    pub state_root: String,
    pub node_count: usize,
    pub drained_node_count: usize,
    pub total_cpu_millis: u64,
    pub free_cpu_millis: u64,
    pub total_memory_mb: u64,
    pub free_memory_mb: u64,
    pub placement_decisions: PlacementDecisionCounts,
}

#[derive(Debug)]
struct PlacementCandidate {
    key: String,
    version: u64,
    node: NodeInventory,
    score: f64,
    remaining_cpu_millis: u32,
    remaining_memory_mb: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateNodeRequest {
    region: String,
    #[serde(default)]
    scheduler_pool: Option<String>,
    cpu_millis: u32,
    memory_mb: u64,
}

/// Scheduler service.
#[derive(Debug, Clone)]
pub struct SchedulerService {
    nodes: DocumentStore<NodeInventory>,
    decisions: DocumentStore<PlacementDecision>,
    // The beta scheduler has no cross-store transaction, so placement admission
    // and decision persistence are serialized locally and guarded by a
    // shared-state lock file to prevent duplicate reservation across processes
    // that point at the same scheduler state root.
    placement_guard: Arc<Mutex<()>>,
    state_root: PathBuf,
}

impl SchedulerService {
    /// Open the scheduler state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("scheduler");
        Ok(Self {
            nodes: DocumentStore::open(root.join("nodes.json")).await?,
            decisions: DocumentStore::open(root.join("placements.json")).await?,
            placement_guard: Arc::new(Mutex::new(())),
            state_root: root,
        })
    }

    async fn create_node(&self, request: CreateNodeRequest) -> Result<http::Response<ApiBody>> {
        let region = normalize_region(&request.region)?;
        let scheduler_pool = request
            .scheduler_pool
            .as_deref()
            .map(normalize_scheduler_pool)
            .transpose()?
            .unwrap_or_else(default_scheduler_pool);
        if request.cpu_millis == 0 {
            return Err(PlatformError::invalid(
                "cpu_millis must be greater than zero",
            ));
        }
        if request.memory_mb == 0 {
            return Err(PlatformError::invalid(
                "memory_mb must be greater than zero",
            ));
        }
        let id = NodeId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate node id").with_detail(error.to_string())
        })?;
        let node = NodeInventory {
            id: id.clone(),
            region,
            scheduler_pool,
            cpu_millis: request.cpu_millis,
            memory_mb: request.memory_mb,
            free_cpu_millis: request.cpu_millis,
            free_memory_mb: request.memory_mb,
            drained: false,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.nodes.create(id.as_str(), node.clone()).await?;
        json_response(StatusCode::CREATED, &node)
    }

    async fn place(&self, request: PlacementRequest) -> Result<http::Response<ApiBody>> {
        let _placement_guard = self.placement_guard.lock().await;
        let _placement_file_guard = self.acquire_placement_file_guard().await?;

        let workload_id = normalize_workload_id(&request.workload_id)?;
        if request.cpu_millis == 0 {
            return Err(PlatformError::invalid(
                "cpu_millis must be greater than zero",
            ));
        }
        if request.memory_mb == 0 {
            return Err(PlatformError::invalid(
                "memory_mb must be greater than zero",
            ));
        }
        let region = request
            .region
            .as_deref()
            .map(normalize_region)
            .transpose()?;
        let scheduler_pool = request
            .scheduler_pool
            .as_deref()
            .map(normalize_scheduler_pool)
            .transpose()?;

        if let Some(stored) = self.decisions.get(&workload_id).await?
            && !stored.deleted
            && stored.value.node_id.is_some()
        {
            // Placement requests are idempotent by workload id.
            return json_response(StatusCode::OK, &stored.value);
        }

        let demand = PlacementDemand {
            cpu_millis: request.cpu_millis,
            memory_mb: request.memory_mb,
        };

        let mut candidates = self
            .nodes
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(key, record)| (key, record.value, record.version))
            .filter(|(_, node, _)| !node.drained)
            .filter(|(_, node, _)| node.free_cpu_millis >= request.cpu_millis)
            .filter(|(_, node, _)| node.free_memory_mb >= request.memory_mb)
            .filter(|(_, node, _)| region.as_ref().is_none_or(|region| &node.region == region))
            .filter(|(_, node, _)| {
                scheduler_pool
                    .as_ref()
                    .is_none_or(|pool| &node.scheduler_pool == pool)
            })
            .map(|(key, node, version)| PlacementCandidate {
                key,
                version,
                remaining_cpu_millis: node.free_cpu_millis.saturating_sub(request.cpu_millis),
                remaining_memory_mb: node.free_memory_mb.saturating_sub(request.memory_mb),
                score: placement_score(&node, demand),
                node,
            })
            .collect::<Vec<_>>();

        candidates.sort_by(compare_candidates);

        let mut selected = None;
        for candidate in &candidates {
            let mut reserved = candidate.node.clone();
            reserved.free_cpu_millis = reserved.free_cpu_millis.saturating_sub(request.cpu_millis);
            reserved.free_memory_mb = reserved.free_memory_mb.saturating_sub(request.memory_mb);
            reserved
                .metadata
                .touch(sha256_hex(reserved.id.as_str().as_bytes()));

            let reserve_result = self
                .nodes
                .upsert(&candidate.key, reserved, Some(candidate.version))
                .await;

            match reserve_result {
                Ok(_) => {
                    selected = Some(candidate);
                    break;
                }
                Err(error) if matches!(error.code, ErrorCode::Conflict | ErrorCode::NotFound) => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }

        let decision = if let Some(candidate) = selected {
            PlacementDecision {
                workload_id: workload_id.clone(),
                node_id: Some(candidate.node.id.clone()),
                score: candidate.score,
                reason: String::from("selected node with the tightest valid fit"),
            }
        } else {
            PlacementDecision {
                workload_id: workload_id.clone(),
                node_id: None,
                score: 0.0,
                reason: String::from("no node satisfied the requested capacity and reservation"),
            }
        };
        if decision.node_id.is_some() {
            self.decisions
                .upsert(&workload_id, decision.clone(), None)
                .await?;
        }
        json_response(StatusCode::OK, &decision)
    }

    async fn summary(&self) -> Result<SchedulerSummary> {
        let nodes = self
            .nodes
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();

        let node_count = nodes.len();
        let drained_node_count = nodes.iter().filter(|node| node.drained).count();
        let total_cpu_millis = nodes.iter().map(|node| node.cpu_millis as u64).sum::<u64>();
        let free_cpu_millis = nodes
            .iter()
            .map(|node| node.free_cpu_millis as u64)
            .sum::<u64>();
        let total_memory_mb = nodes.iter().map(|node| node.memory_mb).sum::<u64>();
        let free_memory_mb = nodes.iter().map(|node| node.free_memory_mb).sum::<u64>();

        let decisions = self
            .decisions
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        let placed = decisions
            .iter()
            .filter(|decision| decision.node_id.is_some())
            .count();

        Ok(SchedulerSummary {
            state_root: self.state_root.display().to_string(),
            node_count,
            drained_node_count,
            total_cpu_millis,
            free_cpu_millis,
            total_memory_mb,
            free_memory_mb,
            placement_decisions: PlacementDecisionCounts {
                total: decisions.len(),
                placed,
                unplaced: decisions.len().saturating_sub(placed),
            },
        })
    }

    async fn acquire_placement_file_guard(&self) -> Result<PlacementFileGuard> {
        const LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
        const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

        let lock_path = self.state_root.join("placement.lock");
        let deadline = Instant::now() + LOCK_WAIT_TIMEOUT;

        loop {
            match OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&lock_path)
                .await
            {
                Ok(mut file) => {
                    use tokio::io::AsyncWriteExt;
                    let payload = placement_lock_payload();
                    if let Err(error) = file.write_all(payload.as_bytes()).await {
                        let _ = fs::remove_file(&lock_path).await;
                        return Err(PlatformError::unavailable(
                            "failed to initialize scheduler lock file",
                        )
                        .with_detail(error.to_string()));
                    }
                    if let Err(error) = file.flush().await {
                        let _ = fs::remove_file(&lock_path).await;
                        return Err(PlatformError::unavailable(
                            "failed to flush scheduler lock file",
                        )
                        .with_detail(error.to_string()));
                    }
                    return Ok(PlacementFileGuard { path: lock_path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    match fs::metadata(&lock_path).await {
                        Ok(_) => {}
                        Err(metadata_error)
                            if metadata_error.kind() == std::io::ErrorKind::NotFound =>
                        {
                            continue;
                        }
                        Err(metadata_error) => {
                            return Err(PlatformError::unavailable(
                                "failed to inspect scheduler lock file",
                            )
                            .with_detail(metadata_error.to_string()));
                        }
                    }
                    if Instant::now() >= deadline {
                        return Err(PlatformError::new(
                            ErrorCode::Timeout,
                            "timed out waiting for scheduler placement lock",
                        )
                        .with_detail(
                            "remove the scheduler placement lock after verifying no peer process is active",
                        ));
                    }
                    sleep(LOCK_RETRY_INTERVAL).await;
                }
                Err(error) => {
                    return Err(PlatformError::unavailable(
                        "failed to acquire scheduler placement lock",
                    )
                    .with_detail(error.to_string()));
                }
            }
        }
    }
}

#[derive(Debug)]
struct PlacementFileGuard {
    path: PathBuf,
}

impl Drop for PlacementFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn placement_lock_payload() -> String {
    format!(
        "pid={}\nheartbeat_unix_seconds={}\n",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    )
}

fn default_scheduler_pool() -> String {
    String::from(DEFAULT_SCHEDULER_POOL)
}

fn normalize_region(value: &str) -> Result<String> {
    normalize_slug_field(value, "region")
}

fn normalize_scheduler_pool(value: &str) -> Result<String> {
    normalize_slug_field(value, "scheduler_pool")
}

fn normalize_slug_field(value: &str, field: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty")));
    }
    if normalized.len() > 64 {
        return Err(PlatformError::invalid(format!("{field} is too long")));
    }
    if !normalized.chars().all(|character| {
        character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
    }) {
        return Err(PlatformError::invalid(format!(
            "{field} may only contain lowercase ASCII letters, digits, and hyphens"
        )));
    }
    Ok(normalized)
}

fn normalize_workload_id(value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("workload_id may not be empty"));
    }
    if normalized.len() > 128 {
        return Err(PlatformError::invalid("workload_id is too long"));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "workload_id may not contain control characters",
        ));
    }
    Ok(normalized.to_owned())
}

impl HttpService for SchedulerService {
    fn name(&self) -> &'static str {
        "scheduler"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/scheduler")];
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
                (Method::GET, ["scheduler"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                    }),
                )
                .map(Some),
                (Method::GET, ["scheduler", "summary"]) => {
                    let summary = self.summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["scheduler", "nodes"]) => {
                    let nodes = self
                        .nodes
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &nodes).map(Some)
                }
                (Method::POST, ["scheduler", "nodes"]) => {
                    let body: CreateNodeRequest = parse_json(request).await?;
                    self.create_node(body).await.map(Some)
                }
                (Method::GET, ["scheduler", "placements"]) => {
                    let decisions = self
                        .decisions
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &decisions).map(Some)
                }
                (Method::POST, ["scheduler", "placements"]) => {
                    let body: PlacementRequest = parse_json(request).await?;
                    self.place(body).await.map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

/// Score node fit for a demand. Higher is better.
pub fn placement_score(node: &NodeInventory, demand: PlacementDemand) -> f64 {
    let cpu_share = f64::from(demand.cpu_millis) / f64::from(node.cpu_millis.max(1));
    let memory_share = demand.memory_mb as f64 / node.memory_mb.max(1) as f64;
    (cpu_share * 0.6) + (memory_share * 0.4)
}

fn compare_candidates(left: &PlacementCandidate, right: &PlacementCandidate) -> Ordering {
    right
        .score
        .total_cmp(&left.score)
        .then_with(|| left.remaining_cpu_millis.cmp(&right.remaining_cpu_millis))
        .then_with(|| left.remaining_memory_mb.cmp(&right.remaining_memory_mb))
        .then_with(|| left.node.id.as_str().cmp(right.node.id.as_str()))
}

#[cfg(test)]
mod concurrency_tests {
    use std::cmp::Ordering;
    use std::sync::Arc;

    use super::{
        CreateNodeRequest, DEFAULT_SCHEDULER_POOL, NodeInventory, PlacementCandidate,
        PlacementDecision, PlacementDemand, PlacementRequest, SchedulerService, compare_candidates,
        placement_score,
    };
    use http_body_util::BodyExt;
    use tempfile::tempdir;
    use tokio::sync::Barrier;
    use uhost_types::WorkloadId;
    use uhost_types::{NodeId, OwnershipScope, ResourceMetadata};

    #[test]
    fn score_prefers_tighter_fit() {
        let node_a = NodeInventory {
            id: NodeId::generate().unwrap_or_else(|error| panic!("{error}")),
            region: String::from("us-east"),
            scheduler_pool: String::from("general"),
            cpu_millis: 4000,
            memory_mb: 8192,
            free_cpu_millis: 4000,
            free_memory_mb: 8192,
            drained: false,
            metadata: ResourceMetadata::new(OwnershipScope::Platform, None, String::from("etag-a")),
        };
        let mut node_b = node_a.clone();
        node_b.cpu_millis = 1000;
        node_b.memory_mb = 2000;
        node_b.free_cpu_millis = 1000;
        node_b.free_memory_mb = 2000;

        let demand = PlacementDemand {
            cpu_millis: 500,
            memory_mb: 1000,
        };
        assert!(placement_score(&node_b, demand) > placement_score(&node_a, demand));
    }

    #[test]
    fn compare_candidates_is_deterministic_on_ties() {
        let node_a = NodeInventory {
            id: NodeId::parse("nod_aaaaaaaaaa").unwrap_or_else(|error| panic!("{error}")),
            region: String::from("us-east"),
            scheduler_pool: String::from("general"),
            cpu_millis: 4000,
            memory_mb: 8192,
            free_cpu_millis: 3500,
            free_memory_mb: 7000,
            drained: false,
            metadata: ResourceMetadata::new(OwnershipScope::Platform, None, String::from("etag-a")),
        };
        let node_b = NodeInventory {
            id: NodeId::parse("nod_bbbbbbbbbb").unwrap_or_else(|error| panic!("{error}")),
            ..node_a.clone()
        };
        let demand = PlacementDemand {
            cpu_millis: 500,
            memory_mb: 1000,
        };
        let left = PlacementCandidate {
            key: String::from("a"),
            version: 1,
            remaining_cpu_millis: node_a.free_cpu_millis - demand.cpu_millis,
            remaining_memory_mb: node_a.free_memory_mb - demand.memory_mb,
            score: placement_score(&node_a, demand),
            node: node_a,
        };
        let right = PlacementCandidate {
            key: String::from("b"),
            version: 1,
            remaining_cpu_millis: node_b.free_cpu_millis - demand.cpu_millis,
            remaining_memory_mb: node_b.free_memory_mb - demand.memory_mb,
            score: placement_score(&node_b, demand),
            node: node_b,
        };

        assert_eq!(compare_candidates(&left, &right), Ordering::Less);
    }

    #[tokio::test]
    async fn place_skips_deleted_nodes_and_reserves_capacity() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SchedulerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_node(CreateNodeRequest {
                region: String::from("us-east"),
                scheduler_pool: None,
                cpu_millis: 4_000,
                memory_mb: 8_192,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_node(CreateNodeRequest {
                region: String::from("us-east"),
                scheduler_pool: None,
                cpu_millis: 4_000,
                memory_mb: 8_192,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut nodes = service
            .nodes
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        nodes.sort_by_key(|(key, _)| key.clone());
        let (deleted_key, deleted_doc) = nodes
            .first()
            .cloned()
            .unwrap_or_else(|| panic!("missing seeded node"));
        service
            .nodes
            .soft_delete(&deleted_key, Some(deleted_doc.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let active_node = nodes
            .last()
            .map(|(_, doc)| doc.value.id.clone())
            .unwrap_or_else(|| panic!("missing active node"));

        let workload_id = WorkloadId::generate()
            .unwrap_or_else(|error| panic!("{error}"))
            .to_string();
        let _ = service
            .place(PlacementRequest {
                workload_id: workload_id.clone(),
                cpu_millis: 500,
                memory_mb: 512,
                region: Some(String::from("us-east")),
                scheduler_pool: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let decision = service
            .decisions
            .get(&workload_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing decision"));
        assert_eq!(decision.value.node_id, Some(active_node.clone()));

        let reserved_node = service
            .nodes
            .get(active_node.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reserved node"));
        assert_eq!(reserved_node.value.free_cpu_millis, 3_500);
        assert_eq!(reserved_node.value.free_memory_mb, 7_680);
    }

    #[tokio::test]
    async fn place_is_idempotent_for_same_workload_id() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SchedulerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_node(CreateNodeRequest {
                region: String::from("us-east"),
                scheduler_pool: None,
                cpu_millis: 4_000,
                memory_mb: 8_192,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let node_id = service
            .nodes
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, record)| record.value.id.clone())
            .unwrap_or_else(|| panic!("missing node"));

        let workload_id = WorkloadId::generate()
            .unwrap_or_else(|error| panic!("{error}"))
            .to_string();
        let _ = service
            .place(PlacementRequest {
                workload_id: workload_id.clone(),
                cpu_millis: 500,
                memory_mb: 512,
                region: Some(String::from("us-east")),
                scheduler_pool: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let after_first = service
            .nodes
            .get(node_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing node"));
        assert_eq!(after_first.value.free_cpu_millis, 3_500);
        assert_eq!(after_first.value.free_memory_mb, 7_680);

        let _ = service
            .place(PlacementRequest {
                workload_id: workload_id.clone(),
                cpu_millis: 500,
                memory_mb: 512,
                region: Some(String::from("us-east")),
                scheduler_pool: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let after_second = service
            .nodes
            .get(node_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing node"));
        assert_eq!(
            after_second.value.free_cpu_millis,
            after_first.value.free_cpu_millis
        );
        assert_eq!(
            after_second.value.free_memory_mb,
            after_first.value.free_memory_mb
        );
    }

    #[tokio::test]
    async fn denied_placement_is_not_sticky_after_capacity_returns() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SchedulerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let workload_id = WorkloadId::generate()
            .unwrap_or_else(|error| panic!("{error}"))
            .to_string();
        let denied = service
            .place(PlacementRequest {
                workload_id: workload_id.clone(),
                cpu_millis: 500,
                memory_mb: 512,
                region: Some(String::from("us-east")),
                scheduler_pool: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let denied_body = denied
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let denied_decision: PlacementDecision =
            serde_json::from_slice(&denied_body).unwrap_or_else(|error| panic!("{error}"));
        assert!(denied_decision.node_id.is_none());
        assert!(
            service
                .decisions
                .get(&workload_id)
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none(),
            "denied placements should not be cached"
        );

        let created = service
            .create_node(CreateNodeRequest {
                region: String::from("us-east"),
                scheduler_pool: None,
                cpu_millis: 1_000,
                memory_mb: 1_024,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let node_body = created
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let node: NodeInventory =
            serde_json::from_slice(&node_body).unwrap_or_else(|error| panic!("{error}"));

        let admitted = service
            .place(PlacementRequest {
                workload_id: workload_id.clone(),
                cpu_millis: 500,
                memory_mb: 512,
                region: Some(String::from("us-east")),
                scheduler_pool: None,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let admitted_body = admitted
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let admitted_decision: PlacementDecision =
            serde_json::from_slice(&admitted_body).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(admitted_decision.node_id, Some(node.id));
    }

    #[tokio::test]
    async fn create_node_rejects_zero_capacity_and_normalizes_region() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SchedulerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_node(CreateNodeRequest {
                region: String::from("   "),
                scheduler_pool: None,
                cpu_millis: 1_000,
                memory_mb: 1_024,
            })
            .await
            .expect_err("blank region should fail");
        assert!(error.to_string().contains("region"));

        let error = service
            .create_node(CreateNodeRequest {
                region: String::from("us-east"),
                scheduler_pool: None,
                cpu_millis: 0,
                memory_mb: 1_024,
            })
            .await
            .expect_err("zero cpu should fail");
        assert!(error.to_string().contains("cpu_millis"));

        let _ = service
            .create_node(CreateNodeRequest {
                region: String::from(" US-EAST-1 "),
                scheduler_pool: None,
                cpu_millis: 1_000,
                memory_mb: 1_024,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let node = service
            .nodes
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .next()
            .map(|(_, record)| record.value)
            .unwrap_or_else(|| panic!("missing node"));
        assert_eq!(node.region, "us-east-1");
        assert_eq!(node.scheduler_pool, DEFAULT_SCHEDULER_POOL);
    }

    #[tokio::test]
    async fn place_filters_matching_scheduler_pool() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SchedulerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_node(CreateNodeRequest {
                region: String::from("us-east"),
                scheduler_pool: Some(String::from("general")),
                cpu_millis: 4_000,
                memory_mb: 8_192,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let gpu_response = service
            .create_node(CreateNodeRequest {
                region: String::from("us-east"),
                scheduler_pool: Some(String::from("gpu")),
                cpu_millis: 4_000,
                memory_mb: 8_192,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let gpu_body = gpu_response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let gpu_node: NodeInventory =
            serde_json::from_slice(&gpu_body).unwrap_or_else(|error| panic!("{error}"));

        let workload_id = WorkloadId::generate()
            .unwrap_or_else(|error| panic!("{error}"))
            .to_string();
        let decision = service
            .place(PlacementRequest {
                workload_id,
                cpu_millis: 500,
                memory_mb: 512,
                region: Some(String::from("us-east")),
                scheduler_pool: Some(String::from("gpu")),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = decision
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let placement: PlacementDecision =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(placement.node_id, Some(gpu_node.id));
    }

    #[tokio::test]
    async fn place_rejects_blank_workload_ids_and_zero_resource_demands() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SchedulerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .place(PlacementRequest {
                workload_id: String::from("   "),
                cpu_millis: 1_000,
                memory_mb: 1_024,
                region: None,
                scheduler_pool: None,
            })
            .await
            .expect_err("blank workload id should fail");
        assert!(error.to_string().contains("workload_id"));

        let error = service
            .place(PlacementRequest {
                workload_id: String::from("wk-1"),
                cpu_millis: 0,
                memory_mb: 1_024,
                region: None,
                scheduler_pool: None,
            })
            .await
            .expect_err("zero cpu request should fail");
        assert!(error.to_string().contains("cpu_millis"));
    }

    #[tokio::test]
    async fn concurrent_requests_for_same_workload_reserve_capacity_once() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SchedulerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_node(CreateNodeRequest {
                region: String::from("us-east"),
                scheduler_pool: None,
                cpu_millis: 4_000,
                memory_mb: 8_192,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let node_id = service
            .nodes
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, record)| record.value.id.clone())
            .unwrap_or_else(|| panic!("missing node"));

        let workload_id = WorkloadId::generate()
            .unwrap_or_else(|error| panic!("{error}"))
            .to_string();
        let barrier = Arc::new(Barrier::new(8));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let service = service.clone();
            let workload_id = workload_id.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                service
                    .place(PlacementRequest {
                        workload_id,
                        cpu_millis: 500,
                        memory_mb: 512,
                        region: Some(String::from("us-east")),
                        scheduler_pool: None,
                    })
                    .await
            }));
        }

        for task in tasks {
            task.await
                .unwrap_or_else(|error| panic!("placement task panicked: {error}"))
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let reserved_node = service
            .nodes
            .get(node_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reserved node"));
        assert_eq!(reserved_node.value.free_cpu_millis, 3_500);
        assert_eq!(reserved_node.value.free_memory_mb, 7_680);

        let decisions = service
            .decisions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(decisions.len(), 1, "only one decision record should exist");
        assert_eq!(decisions[0].1.value.node_id, Some(node_id));
    }

    #[tokio::test]
    async fn concurrent_unique_workloads_do_not_overcommit_single_node() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SchedulerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_node(CreateNodeRequest {
                region: String::from("us-east"),
                scheduler_pool: None,
                cpu_millis: 1_000,
                memory_mb: 1_024,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let node_id = service
            .nodes
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, record)| record.value.id.clone())
            .unwrap_or_else(|| panic!("missing node"));

        let barrier = Arc::new(Barrier::new(10));
        let mut tasks = Vec::new();
        for _ in 0..10 {
            let service = service.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                let workload_id = WorkloadId::generate()
                    .unwrap_or_else(|error| panic!("{error}"))
                    .to_string();
                barrier.wait().await;
                service
                    .place(PlacementRequest {
                        workload_id,
                        cpu_millis: 1_000,
                        memory_mb: 1_024,
                        region: Some(String::from("us-east")),
                        scheduler_pool: None,
                    })
                    .await
            }));
        }

        let mut admitted = 0_usize;
        let mut denied = 0_usize;
        for task in tasks {
            let response = task
                .await
                .unwrap_or_else(|error| panic!("placement task panicked: {error}"))
                .unwrap_or_else(|error| panic!("{error}"));
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            let decision: PlacementDecision =
                serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));
            if decision.node_id.is_some() {
                admitted += 1;
            } else {
                denied += 1;
            }
        }

        assert_eq!(admitted, 1, "only one workload should fit the node");
        assert_eq!(denied, 9, "remaining placements should be denied");

        let reserved_node = service
            .nodes
            .get(node_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reserved node"));
        assert_eq!(reserved_node.value.free_cpu_millis, 0);
        assert_eq!(reserved_node.value.free_memory_mb, 0);
    }

    #[tokio::test]
    async fn placement_lock_file_exists_while_guard_is_held() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SchedulerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _guard = service
            .acquire_placement_file_guard()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            std::fs::metadata(service.state_root.join("placement.lock")).is_ok(),
            "lock file should exist while the guard is held"
        );
    }

    #[tokio::test]
    async fn placement_lock_is_released_on_drop() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SchedulerService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let lock_path = service.state_root.join("placement.lock");
        let guard = service
            .acquire_placement_file_guard()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(std::fs::metadata(&lock_path).is_ok());
        drop(guard);
        assert!(
            std::fs::metadata(&lock_path).is_err(),
            "lock file should be removed when the guard drops"
        );
        let _guard = service
            .acquire_placement_file_guard()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }
}

#[cfg(test)]
mod summary_tests {
    use tempfile::tempdir;

    use super::{DEFAULT_SCHEDULER_POOL, NodeInventory, PlacementDecision, SchedulerService};
    use uhost_core::{PlatformError, Result, sha256_hex};
    use uhost_store::DocumentStore;
    use uhost_types::{NodeId, OwnershipScope, ResourceMetadata};

    async fn create_node(
        store: &DocumentStore<NodeInventory>,
        id: &str,
        region: &str,
        cpu: u32,
        memory: u64,
        drained: bool,
    ) -> Result<()> {
        let node_id = NodeId::parse(id).map_err(|error| {
            PlatformError::invalid("invalid node id").with_detail(error.to_string())
        })?;
        let node = NodeInventory {
            id: node_id,
            region: region.to_owned(),
            scheduler_pool: String::from(DEFAULT_SCHEDULER_POOL),
            cpu_millis: cpu,
            memory_mb: memory,
            free_cpu_millis: cpu / 2,
            free_memory_mb: memory / 2,
            drained,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_owned()),
                sha256_hex(id.as_bytes()),
            ),
        };
        store.create(id, node).await?;
        Ok(())
    }

    #[tokio::test]
    async fn summary_aggregates_inventory_and_decisions() {
        let temp = tempdir().unwrap();
        let service = SchedulerService::open(temp.path()).await.unwrap();
        let nodes_store =
            DocumentStore::<NodeInventory>::open(service.state_root.join("nodes.json"))
                .await
                .unwrap();
        let decisions_store =
            DocumentStore::<PlacementDecision>::open(service.state_root.join("placements.json"))
                .await
                .unwrap();

        create_node(&nodes_store, "nod_aaaaaaaaaa", "us-east", 4000, 8192, false)
            .await
            .unwrap();
        create_node(&nodes_store, "nod_bbbbbbbbbb", "us-east", 2000, 4096, true)
            .await
            .unwrap();

        decisions_store
            .create(
                "placement-1",
                PlacementDecision {
                    workload_id: String::from("wrk-1"),
                    node_id: Some(NodeId::parse("nod_aaaaaaaaaa").unwrap()),
                    score: 0.5,
                    reason: String::from("sample"),
                },
            )
            .await
            .unwrap();
        decisions_store
            .create(
                "placement-2",
                PlacementDecision {
                    workload_id: String::from("wrk-2"),
                    node_id: None,
                    score: 0.0,
                    reason: String::from("no capacity"),
                },
            )
            .await
            .unwrap();

        let summary = service.summary().await.unwrap();

        assert_eq!(summary.node_count, 2);
        assert_eq!(summary.drained_node_count, 1);
        assert_eq!(summary.placement_decisions.total, 2);
        assert_eq!(summary.placement_decisions.placed, 1);
        assert_eq!(summary.placement_decisions.unplaced, 1);
    }
}
