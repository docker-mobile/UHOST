//! Ingress route service.
//!
//! The ingress service is the platform policy point for north-south traffic.
//! This implementation keeps the durable control-plane model explicit and
//! dependency-starved while still exposing the core behaviors operators need:
//! weighted backend selection, sticky sessions, health and circuit controls,
//! request-level admission/rate-limiting, and auditable decision trails.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use http::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use uhost_api::{ApiBody, json_response, parse_json, parse_query, path_segments};
use uhost_core::{
    ErrorCode, PlatformError, RequestContext, Result, canonicalize_hostname, sha256_hex,
    validate_domain_name,
};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{AuditLog, DocumentStore, DurableOutbox, StoredDocument};
use uhost_types::{
    AuditActor, AuditId, ChangeRequestId, EdgeDnsBinding, EdgeExposureIntent,
    EdgePrivateNetworkAttachment, EdgePublication, EdgePublicationTarget, EdgePublicationTargetId,
    EdgeSecurityPolicyAttachment, EventHeader, EventPayload, GovernanceChangeAuthorization,
    GovernanceRequestProvenance, OwnershipScope, PlatformEvent, PolicyId, PrivateNetworkId,
    PrivateNetworkTopologyReadiness, Protocol, ResourceMetadata, RouteId, ServiceEvent, ZoneId,
};

fn default_tls_mode() -> String {
    String::from("redirect_https")
}

fn default_cookie_name() -> String {
    String::from("uhost_route")
}

fn default_health_path() -> String {
    String::from("/healthz")
}

fn default_edge_request_path() -> String {
    String::from("/")
}

fn default_max_bot_score() -> u16 {
    1_000
}

fn default_edge_ddos_mode() -> String {
    String::from("monitor")
}

fn default_locality_fallback_to_any_healthy() -> bool {
    true
}

fn default_steering_audit_locality() -> String {
    String::from("not_evaluated")
}

fn default_steering_audit_canary_pool() -> String {
    String::from("not_evaluated")
}

/// One backend endpoint in a route pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteBackend {
    /// Backend id stable within a route.
    pub id: String,
    /// Upstream target (`http://`, `https://`, `service://`, `tcp://`).
    pub target: String,
    /// Weighted load balancing weight.
    pub weight: u16,
    /// Optional region hint used for locality-aware steering.
    #[serde(default)]
    pub region: Option<String>,
    /// Optional cell hint used for cell-aware steering.
    #[serde(default)]
    pub cell: Option<String>,
    /// Marks the backend as part of the canary pool.
    #[serde(default)]
    pub canary: bool,
    /// Last known health state.
    pub healthy: bool,
    /// Consecutive observed failures.
    pub failure_count: u32,
    /// Last health check/update timestamp.
    pub last_checked_at: Option<OffsetDateTime>,
}

/// L7 health check policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheckPolicy {
    pub path: String,
    pub interval_seconds: u32,
    pub timeout_ms: u32,
    pub unhealthy_threshold: u16,
    pub healthy_threshold: u16,
}

impl Default for HealthCheckPolicy {
    fn default() -> Self {
        Self {
            path: default_health_path(),
            interval_seconds: 10,
            timeout_ms: 2_000,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        }
    }
}

/// Retry policy used by data-plane adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub initial_backoff_ms: u32,
    pub max_backoff_ms: u32,
    pub retry_on_5xx: bool,
    pub retry_on_connect_failure: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 50,
            max_backoff_ms: 400,
            retry_on_5xx: true,
            retry_on_connect_failure: true,
        }
    }
}

/// Circuit breaker policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitBreakerPolicy {
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub open_interval_seconds: u32,
}

impl Default for CircuitBreakerPolicy {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            open_interval_seconds: 30,
        }
    }
}

/// End-to-end timeout policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutPolicy {
    pub connect_timeout_ms: u32,
    pub request_timeout_ms: u32,
    pub idle_timeout_ms: u32,
}

impl Default for TimeoutPolicy {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 2_000,
            request_timeout_ms: 30_000,
            idle_timeout_ms: 60_000,
        }
    }
}

/// Header normalization policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderPolicy {
    pub normalize_host: bool,
    pub strip_hop_by_hop: bool,
    pub set_forwarded_headers: bool,
}

impl Default for HeaderPolicy {
    fn default() -> Self {
        Self {
            normalize_host: true,
            strip_hop_by_hop: true,
            set_forwarded_headers: true,
        }
    }
}

/// Compression hints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionPolicy {
    pub enabled: bool,
    pub min_size_bytes: u32,
}

impl Default for CompressionPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            min_size_bytes: 1_024,
        }
    }
}

/// Per-route token bucket configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    pub requests_per_minute: u32,
    pub burst: u32,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            requests_per_minute: 600,
            burst: 120,
        }
    }
}

/// Sticky session policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StickySessionPolicy {
    pub enabled: bool,
    pub cookie_name: String,
    pub ttl_seconds: u32,
}

impl Default for StickySessionPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            cookie_name: default_cookie_name(),
            ttl_seconds: 86_400,
        }
    }
}

/// Service identity constraints for a route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServiceIdentityPolicy {
    pub required: bool,
    pub require_mtls: bool,
    pub allowed_subject_prefixes: Vec<String>,
}

/// Locality preference used when choosing a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LocalityMode {
    /// Do not apply locality-aware steering.
    #[default]
    None,
    /// Prefer backends in the requested region.
    Region,
    /// Prefer backends in the requested cell, then region.
    Cell,
}

/// Canary steering controls for one ingress route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CanarySteeringPolicy {
    /// Percent of traffic routed to canary backends when both pools are healthy.
    #[serde(default)]
    pub traffic_percent: u8,
}

/// Route-level steering policy used by ingress admission and backend selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SteeringPolicy {
    /// Locality preference applied before weighted selection.
    #[serde(default)]
    pub locality_mode: LocalityMode,
    /// Whether locality misses may fall back to any remaining healthy backend.
    #[serde(default = "default_locality_fallback_to_any_healthy")]
    pub fallback_to_any_healthy: bool,
    /// Canary traffic split configuration.
    #[serde(default)]
    pub canary: CanarySteeringPolicy,
}

impl Default for SteeringPolicy {
    fn default() -> Self {
        Self {
            locality_mode: LocalityMode::None,
            fallback_to_any_healthy: true,
            canary: CanarySteeringPolicy::default(),
        }
    }
}

/// Circuit state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Mutable policy state for circuit decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePolicyState {
    pub circuit_state: CircuitState,
    pub opened_at: Option<OffsetDateTime>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_transition_at: OffsetDateTime,
}

impl Default for RoutePolicyState {
    fn default() -> Self {
        Self {
            circuit_state: CircuitState::Closed,
            opened_at: None,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_transition_at: OffsetDateTime::now_utc(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DnsZoneHook {
    id: String,
    domain: String,
    verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct InspectionProfileHook {
    id: String,
    name: String,
    #[serde(default)]
    blocked_countries: Vec<String>,
    #[serde(default)]
    min_waf_score: u16,
    #[serde(default = "default_max_bot_score")]
    max_bot_score: u16,
    #[serde(default = "default_edge_ddos_mode")]
    ddos_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrivateNetworkHook {
    id: PrivateNetworkId,
    name: String,
    cidr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrivateTopologySubnetHook {
    private_network_id: PrivateNetworkId,
    #[serde(default)]
    route_table_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrivateTopologyRouteTableHook {
    id: String,
    private_network_id: PrivateNetworkId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrivateTopologyNextHopHook {
    id: String,
    private_network_id: PrivateNetworkId,
    kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrivateTopologyRouteHook {
    id: String,
    private_network_id: PrivateNetworkId,
    route_table_id: String,
    next_hop_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrivateTopologyServiceConnectAttachmentHook {
    private_network_id: PrivateNetworkId,
    private_route_id: String,
    route_table_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrivateTopologyNatGatewayHook {
    private_network_id: PrivateNetworkId,
    #[serde(default)]
    route_table_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrivateTopologyTransitAttachmentHook {
    private_network_id: PrivateNetworkId,
    #[serde(default)]
    route_table_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrivateTopologyVpnConnectionHook {
    private_network_id: PrivateNetworkId,
    #[serde(default)]
    route_table_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrivateTopologyPeeringConnectionHook {
    private_network_id: PrivateNetworkId,
    #[serde(default)]
    route_table_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GovernanceChangeRequestMirror {
    id: ChangeRequestId,
    state: String,
    #[serde(default, flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MailDomainHook {
    id: String,
    domain: String,
    #[serde(default)]
    zone_id: Option<String>,
    #[serde(default)]
    verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MailReputationHook {
    domain_id: String,
    #[serde(default)]
    suspended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MailDeadLetterHook {
    domain_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PolicyRecordHook {
    id: String,
    resource_kind: String,
    action: String,
    effect: String,
    #[serde(default)]
    selector: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PolicyApprovalHook {
    #[serde(default)]
    subject: String,
    #[serde(default)]
    approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GovernanceLegalHoldHook {
    #[serde(default)]
    active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GovernanceAuditCheckpointHook {
    recorded_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AbuseQuarantineHook {
    #[serde(default)]
    subject_kind: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    deny_network: bool,
    #[serde(default)]
    deny_mail_relay: bool,
    expires_at: Option<OffsetDateTime>,
}

/// Durable DNS-binding evaluation captured during a publication mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteDnsBindingEvaluationSnapshot {
    /// Bound managed zone identifier.
    pub zone_id: ZoneId,
    /// Zone domain authorized for the hostname.
    pub domain: String,
    /// Whether the zone was verified when the mutation executed.
    pub verified: bool,
    /// Stable operator-readable rationale for this snapshot.
    pub rationale: String,
}

/// Durable security-policy evaluation captured during a publication mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteSecurityPolicyEvaluationSnapshot {
    /// Inspection profile identifier attached to the route.
    pub inspection_profile_id: PolicyId,
    /// Inspection profile name captured at mutation time.
    pub inspection_profile_name: String,
    /// Blocked source countries captured at mutation time.
    #[serde(default)]
    pub blocked_countries: Vec<String>,
    /// Minimum WAF score enforced by the captured profile.
    pub min_waf_score: u16,
    /// Maximum bot score enforced by the captured profile.
    pub max_bot_score: u16,
    /// DDoS mode captured from the inspection profile.
    pub ddos_mode: String,
    /// Stable operator-readable rationale for this snapshot.
    pub rationale: String,
}

/// Durable private-network evaluation captured during a publication mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePrivateNetworkEvaluationSnapshot {
    /// Private-network identifier attached to the route.
    pub private_network_id: PrivateNetworkId,
    /// Private-network name captured at mutation time.
    pub private_network_name: String,
    /// Private-network CIDR captured at mutation time.
    pub cidr: String,
    /// Topology-readiness proof captured at mutation time.
    #[serde(default)]
    pub topology: PrivateNetworkTopologyReadiness,
    /// Stable operator-readable rationale for this snapshot.
    pub rationale: String,
}

/// Durable publication evaluation captured during route creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePublicationEvaluationSnapshot {
    /// Timestamp when the mutation captured this snapshot.
    pub captured_at: OffsetDateTime,
    /// Whether the publication mutation was admitted.
    pub admitted: bool,
    /// Stable operator-readable rationale for the route-level decision.
    pub rationale: String,
    /// Optional DNS-binding evidence captured at mutation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_binding: Option<RouteDnsBindingEvaluationSnapshot>,
    /// Optional security-policy evidence captured at mutation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_policy: Option<RouteSecurityPolicyEvaluationSnapshot>,
    /// Optional private-network evidence captured at mutation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_network: Option<RoutePrivateNetworkEvaluationSnapshot>,
}

/// Ingress route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteRecord {
    pub id: RouteId,
    pub hostname: String,
    /// Legacy single-target field retained for backwards-compatible decoding.
    #[serde(default)]
    pub target: String,
    pub protocol: Protocol,
    pub tls_mode: String,
    pub metadata: ResourceMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
    #[serde(default)]
    pub publication: EdgePublication,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_evaluation: Option<RoutePublicationEvaluationSnapshot>,
    #[serde(default)]
    pub backends: Vec<RouteBackend>,
    #[serde(default)]
    pub health_check: HealthCheckPolicy,
    #[serde(default)]
    pub retry_policy: RetryPolicy,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerPolicy,
    #[serde(default)]
    pub timeout_policy: TimeoutPolicy,
    #[serde(default)]
    pub header_policy: HeaderPolicy,
    #[serde(default)]
    pub compression_policy: CompressionPolicy,
    #[serde(default)]
    pub rate_limit_policy: RateLimitPolicy,
    #[serde(default)]
    pub sticky_session_policy: StickySessionPolicy,
    #[serde(default)]
    pub service_identity_policy: ServiceIdentityPolicy,
    #[serde(default)]
    pub steering_policy: SteeringPolicy,
    #[serde(default)]
    pub policy_state: RoutePolicyState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateRouteBackendRequest {
    target: String,
    weight: Option<u16>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    cell: Option<String>,
    #[serde(default)]
    canary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateRouteDnsBindingRequest {
    zone_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateRouteSecurityPolicyAttachmentRequest {
    inspection_profile_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateRoutePrivateNetworkAttachmentRequest {
    private_network_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateRoutePublicationTargetRequest {
    cell: String,
    region: String,
    #[serde(default)]
    failover_group: Option<String>,
    #[serde(default)]
    drain: bool,
    tls_owner: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateRoutePublicationRequest {
    #[serde(default)]
    exposure: Option<String>,
    #[serde(default)]
    dns_binding: Option<CreateRouteDnsBindingRequest>,
    #[serde(default)]
    security_policy: Option<CreateRouteSecurityPolicyAttachmentRequest>,
    #[serde(default)]
    private_network: Option<CreateRoutePrivateNetworkAttachmentRequest>,
    #[serde(default)]
    targets: Vec<CreateRoutePublicationTargetRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateRouteRequest {
    hostname: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    backends: Vec<CreateRouteBackendRequest>,
    protocol: String,
    #[serde(default)]
    sticky_sessions: bool,
    #[serde(default = "default_tls_mode")]
    tls_mode: String,
    #[serde(default)]
    publication: Option<CreateRoutePublicationRequest>,
    #[serde(default)]
    health_check: Option<HealthCheckPolicy>,
    #[serde(default)]
    retry_policy: Option<RetryPolicy>,
    #[serde(default)]
    circuit_breaker: Option<CircuitBreakerPolicy>,
    #[serde(default)]
    timeout_policy: Option<TimeoutPolicy>,
    #[serde(default)]
    header_policy: Option<HeaderPolicy>,
    #[serde(default)]
    compression_policy: Option<CompressionPolicy>,
    #[serde(default)]
    rate_limit_policy: Option<RateLimitPolicy>,
    #[serde(default)]
    sticky_session_policy: Option<StickySessionPolicy>,
    #[serde(default)]
    service_identity_policy: Option<ServiceIdentityPolicy>,
    #[serde(default)]
    steering_policy: Option<SteeringPolicy>,
    #[serde(default)]
    change_request_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ResolveRouteRequest {
    hostname: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EvaluateRouteRequest {
    hostname: String,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    source_identity: Option<String>,
    #[serde(default)]
    client_ip: Option<String>,
    #[serde(default)]
    session_key: Option<String>,
    #[serde(default)]
    request_path: Option<String>,
    #[serde(default)]
    source_country: Option<String>,
    #[serde(default)]
    waf_score: Option<u16>,
    #[serde(default)]
    bot_score: Option<u16>,
    #[serde(default)]
    ddos_suspected: Option<bool>,
    #[serde(default)]
    private_network_id: Option<String>,
    #[serde(default)]
    preferred_region: Option<String>,
    #[serde(default)]
    preferred_cell: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EvaluateRouteResponse {
    admitted: bool,
    route_id: Option<String>,
    selected_backend_id: Option<String>,
    selected_backend: Option<String>,
    reason: String,
    circuit_state: String,
    timeout_policy: Option<TimeoutPolicy>,
    retry_policy: Option<RetryPolicy>,
    sticky_cookie_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IngressEdgePolicyDecisionAudit {
    inspection_profile_id: String,
    inspection_profile_name: String,
    request_path: String,
    verdict: String,
    reason: String,
    #[serde(default)]
    source_country: Option<String>,
    #[serde(default)]
    waf_score: Option<u16>,
    #[serde(default)]
    bot_score: Option<u16>,
    #[serde(default)]
    ddos_suspected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SteeringAuditEvidence {
    denial_reason: Option<String>,
    selected_locality: String,
    selected_canary_pool: String,
}

impl Default for SteeringAuditEvidence {
    fn default() -> Self {
        Self {
            denial_reason: None,
            selected_locality: default_steering_audit_locality(),
            selected_canary_pool: default_steering_audit_canary_pool(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RouteHealthReportRequest {
    backend_id: String,
    healthy: bool,
    #[serde(default)]
    observed_latency_ms: Option<u64>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RouteCircuitEventRequest {
    success: bool,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IngressDecisionAudit {
    id: AuditId,
    route_id: Option<RouteId>,
    hostname: String,
    verdict: String,
    reason: String,
    selected_backend: Option<String>,
    selected_backend_id: Option<String>,
    source_identity: Option<String>,
    client_ip: Option<String>,
    #[serde(default)]
    edge_policy: Option<IngressEdgePolicyDecisionAudit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    steering_denial_reason: Option<String>,
    #[serde(default = "default_steering_audit_locality")]
    selected_locality: String,
    #[serde(default = "default_steering_audit_canary_pool")]
    selected_canary_pool: String,
    observed_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IngressAuditSummary {
    total: u64,
    allow: u64,
    deny: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressSummaryResponse {
    pub total_routes: usize,
    pub total_sites: usize,
    pub total_backends: usize,
    pub total_dns_bindings: usize,
    pub total_dns_zones: usize,
    pub dns_ready_domains: usize,
    pub dns_pending_domains: usize,
    pub total_edge_policy_routes: usize,
    pub total_inspection_profiles: usize,
    pub total_private_routes: usize,
    pub total_private_networks: usize,
    pub total_publication_targets: usize,
    pub draining_publication_targets: usize,
    pub publication_regions: usize,
    pub publication_cells: usize,
    pub publication_failover_groups: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureEvidenceResponse {
    pub generated_at: OffsetDateTime,
    pub summary: ExposureEvidenceSummary,
    pub routes: Vec<ExposureEvidenceRoute>,
    pub policy: ExposureEvidencePolicySignals,
    pub governance: ExposureEvidenceGovernanceSignals,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureEvidenceSummary {
    pub total_routes: usize,
    pub public_routes: usize,
    pub private_routes: usize,
    pub routes_requiring_attention: usize,
    pub routes_with_verified_dns: usize,
    pub routes_without_active_targets: usize,
    pub routes_with_mail_risk: usize,
    pub routes_with_policy_matches: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureEvidenceRoute {
    pub route_id: String,
    pub hostname: String,
    pub protocol: String,
    pub exposure: String,
    pub active_publication_targets: usize,
    pub draining_publication_targets: usize,
    pub healthy_backends: usize,
    pub total_backends: usize,
    pub circuit_state: String,
    pub dns: ExposureEvidenceDnsSignals,
    pub netsec: ExposureEvidenceNetsecSignals,
    pub mail: ExposureEvidenceMailSignals,
    pub policy: ExposureEvidencePolicyMatchSignals,
    pub attention_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureEvidenceDnsSignals {
    pub binding_present: bool,
    pub zone_id: Option<String>,
    pub zone_domain: Option<String>,
    pub zone_verified: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureEvidenceNetsecSignals {
    pub inspection_profile_id: Option<String>,
    pub inspection_profile_name: Option<String>,
    pub inspection_profile_present: bool,
    pub private_network_id: Option<String>,
    pub private_network_present: bool,
    pub private_network_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_network_topology: Option<PrivateNetworkTopologyReadiness>,
    pub hostname_quarantine_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureEvidenceMailSignals {
    pub related_domains: Vec<String>,
    pub verified_domains: usize,
    pub suspended_domains: usize,
    pub active_relay_quarantines: usize,
    pub dead_letter_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureEvidencePolicyMatchSignals {
    pub matched_policies: usize,
    pub matched_allow_policies: usize,
    pub matched_deny_policies: usize,
    pub matched_policy_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureEvidencePolicySignals {
    pub total_policies: usize,
    pub allow_policies: usize,
    pub deny_policies: usize,
    pub matched_route_policies: usize,
    pub total_approvals: usize,
    pub pending_approvals: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureEvidenceGovernanceSignals {
    pub total_change_requests: usize,
    pub pending_change_requests: usize,
    pub approved_change_requests: usize,
    pub applied_change_requests: usize,
    pub active_legal_holds: usize,
    pub audit_checkpoints: usize,
    pub latest_checkpoint_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RateCounter {
    window_start_minute: i64,
    count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CandidateSelection<'a> {
    Candidates {
        candidates: Vec<&'a RouteBackend>,
        selected_locality: String,
    },
    Denied {
        reason: String,
        selected_locality: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BackendSelectionOutcome {
    Selected {
        backend: RouteBackend,
        steering: SteeringAuditEvidence,
    },
    Denied(SteeringAuditEvidence),
}

/// Ingress service.
#[derive(Debug, Clone)]
pub struct IngressService {
    routes: DocumentStore<RouteRecord>,
    decision_audit: DocumentStore<IngressDecisionAudit>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    governance_change_requests: DocumentStore<GovernanceChangeRequestMirror>,
    dns_zones: DocumentStore<DnsZoneHook>,
    inspection_profiles: DocumentStore<InspectionProfileHook>,
    private_networks: DocumentStore<PrivateNetworkHook>,
    subnets: DocumentStore<PrivateTopologySubnetHook>,
    route_tables: DocumentStore<PrivateTopologyRouteTableHook>,
    next_hops: DocumentStore<PrivateTopologyNextHopHook>,
    private_routes: DocumentStore<PrivateTopologyRouteHook>,
    service_connect_attachments: DocumentStore<PrivateTopologyServiceConnectAttachmentHook>,
    nat_gateways: DocumentStore<PrivateTopologyNatGatewayHook>,
    transit_attachments: DocumentStore<PrivateTopologyTransitAttachmentHook>,
    vpn_connections: DocumentStore<PrivateTopologyVpnConnectionHook>,
    peering_connections: DocumentStore<PrivateTopologyPeeringConnectionHook>,
    mail_domains: DocumentStore<MailDomainHook>,
    mail_reputation: DocumentStore<MailReputationHook>,
    mail_dead_letters: DocumentStore<MailDeadLetterHook>,
    policy_records: DocumentStore<PolicyRecordHook>,
    policy_approvals: DocumentStore<PolicyApprovalHook>,
    governance_legal_holds: DocumentStore<GovernanceLegalHoldHook>,
    governance_audit_checkpoints: DocumentStore<GovernanceAuditCheckpointHook>,
    abuse_quarantines: DocumentStore<AbuseQuarantineHook>,
    state_root: PathBuf,
    rate_counters: Arc<Mutex<HashMap<String, RateCounter>>>,
    rate_limit_last_cleanup_minute: Arc<Mutex<i64>>,
    route_rr_cursor: Arc<Mutex<HashMap<String, u64>>>,
}

impl IngressService {
    /// Open ingress state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("ingress");
        let abuse_quarantine_path = state_root.as_ref().join("abuse").join("quarantines.json");
        let service = Self {
            routes: DocumentStore::open(root.join("routes.json")).await?,
            decision_audit: DocumentStore::open(root.join("flow_audit.json")).await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            governance_change_requests: DocumentStore::open(
                state_root
                    .as_ref()
                    .join("governance")
                    .join("change_requests.json"),
            )
            .await?,
            dns_zones: DocumentStore::open(state_root.as_ref().join("dns").join("zones.json"))
                .await?,
            inspection_profiles: DocumentStore::open(
                state_root
                    .as_ref()
                    .join("netsec")
                    .join("inspection_profiles.json"),
            )
            .await?,
            private_networks: DocumentStore::open(
                state_root
                    .as_ref()
                    .join("netsec")
                    .join("private_networks.json"),
            )
            .await?,
            subnets: DocumentStore::open(state_root.as_ref().join("netsec").join("subnets.json"))
                .await?,
            route_tables: DocumentStore::open(
                state_root.as_ref().join("netsec").join("route_tables.json"),
            )
            .await?,
            next_hops: DocumentStore::open(
                state_root.as_ref().join("netsec").join("next_hops.json"),
            )
            .await?,
            private_routes: DocumentStore::open(
                state_root.as_ref().join("netsec").join("routes.json"),
            )
            .await?,
            service_connect_attachments: DocumentStore::open(
                state_root
                    .as_ref()
                    .join("netsec")
                    .join("service_connect_attachments.json"),
            )
            .await?,
            nat_gateways: DocumentStore::open(
                state_root.as_ref().join("netsec").join("nat_gateways.json"),
            )
            .await?,
            transit_attachments: DocumentStore::open(
                state_root
                    .as_ref()
                    .join("netsec")
                    .join("transit_attachments.json"),
            )
            .await?,
            vpn_connections: DocumentStore::open(
                state_root
                    .as_ref()
                    .join("netsec")
                    .join("vpn_connections.json"),
            )
            .await?,
            peering_connections: DocumentStore::open(
                state_root.as_ref().join("netsec").join("peerings.json"),
            )
            .await?,
            mail_domains: DocumentStore::open(
                state_root.as_ref().join("mail").join("domains.json"),
            )
            .await?,
            mail_reputation: DocumentStore::open(
                state_root.as_ref().join("mail").join("reputation.json"),
            )
            .await?,
            mail_dead_letters: DocumentStore::open(
                state_root.as_ref().join("mail").join("dead_letters.json"),
            )
            .await?,
            policy_records: DocumentStore::open(
                state_root.as_ref().join("policy").join("policies.json"),
            )
            .await?,
            policy_approvals: DocumentStore::open(
                state_root.as_ref().join("policy").join("approvals.json"),
            )
            .await?,
            governance_legal_holds: DocumentStore::open(
                state_root
                    .as_ref()
                    .join("governance")
                    .join("legal_holds.json"),
            )
            .await?,
            governance_audit_checkpoints: DocumentStore::open(
                state_root
                    .as_ref()
                    .join("governance")
                    .join("audit_checkpoints.json"),
            )
            .await?,
            abuse_quarantines: DocumentStore::open(abuse_quarantine_path).await?,
            state_root: root,
            rate_counters: Arc::new(Mutex::new(HashMap::new())),
            rate_limit_last_cleanup_minute: Arc::new(Mutex::new(i64::MIN)),
            route_rr_cursor: Arc::new(Mutex::new(HashMap::new())),
        };
        service.reconcile_routes().await?;
        Ok(service)
    }

    async fn reconcile_routes(&self) -> Result<()> {
        // This is legacy-shape backfill during service open, not general route
        // reconciliation: mirror the old single `target` field into `backends`,
        // normalize zero/empty backend defaults, and restore the default sticky
        // cookie name where older records omitted it.
        for (key, stored) in self.routes.list().await? {
            if stored.deleted {
                continue;
            }
            let mut route = stored.value;
            let mut changed = false;
            if route.backends.is_empty() && !route.target.trim().is_empty() {
                route.backends.push(RouteBackend {
                    id: String::from("backend-1"),
                    target: route.target.clone(),
                    weight: 1,
                    region: None,
                    cell: None,
                    canary: false,
                    healthy: true,
                    failure_count: 0,
                    last_checked_at: None,
                });
                changed = true;
            }
            if route.target.trim().is_empty()
                && let Some(first) = route.backends.first()
            {
                route.target = first.target.clone();
                changed = true;
            }
            for backend in &mut route.backends {
                if backend.weight == 0 {
                    backend.weight = 1;
                    changed = true;
                }
            }
            if route.sticky_session_policy.cookie_name.trim().is_empty() {
                route.sticky_session_policy.cookie_name = default_cookie_name();
                changed = true;
            }
            if changed {
                self.routes
                    .upsert(&key, route, Some(stored.version))
                    .await?;
            }
        }
        Ok(())
    }

    async fn validate_route_zone_binding(
        &self,
        zone_id: &ZoneId,
        hostname: &str,
    ) -> Result<DnsZoneHook> {
        let stored_zone = self
            .dns_zones
            .get(zone_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("zone does not exist"))?;
        if stored_zone.deleted {
            return Err(PlatformError::not_found("zone does not exist"));
        }

        let zone = stored_zone.value;
        if zone.id != zone_id.as_str() {
            return Err(PlatformError::conflict(
                "zone record is inconsistent with requested zone_id",
            ));
        }
        let zone_domain = validate_domain_name(&zone.domain)?;
        let allowed_suffix = format!(".{zone_domain}");
        if hostname != zone_domain && !hostname.ends_with(&allowed_suffix) {
            return Err(PlatformError::forbidden(
                "zone_id is not authorized for this ingress hostname",
            ));
        }

        Ok(zone)
    }

    async fn validate_inspection_profile_attachment(
        &self,
        inspection_profile_id: &PolicyId,
    ) -> Result<InspectionProfileHook> {
        let stored_profile = self
            .inspection_profiles
            .get(inspection_profile_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("inspection profile does not exist"))?;
        if stored_profile.deleted {
            return Err(PlatformError::not_found(
                "inspection profile does not exist",
            ));
        }

        let profile = stored_profile.value;
        if profile.id != inspection_profile_id.as_str() {
            return Err(PlatformError::conflict(
                "inspection profile record is inconsistent with requested inspection_profile_id",
            ));
        }

        Ok(profile)
    }

    async fn validate_private_network_attachment(
        &self,
        private_network_id: &PrivateNetworkId,
    ) -> Result<PrivateNetworkHook> {
        let stored_network = self
            .private_networks
            .get(private_network_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("private network does not exist"))?;
        if stored_network.deleted {
            return Err(PlatformError::not_found("private network does not exist"));
        }

        let network = stored_network.value;
        if &network.id != private_network_id {
            return Err(PlatformError::conflict(
                "private network record is inconsistent with requested private_network_id",
            ));
        }

        Ok(network)
    }

    async fn private_network_topology_readiness(
        &self,
        private_network_id: &PrivateNetworkId,
    ) -> Result<PrivateNetworkTopologyReadiness> {
        let route_table_ids = self
            .route_tables
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| record.private_network_id == *private_network_id)
            .map(|record| record.id)
            .collect::<HashSet<_>>();
        let route_table_count = route_table_ids.len();

        let subnets = self
            .subnets
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| record.private_network_id == *private_network_id)
            .collect::<Vec<_>>();
        let subnet_count = subnets.len();
        let subnets_with_route_table_count = subnets
            .iter()
            .filter(|record| {
                record
                    .route_table_id
                    .as_ref()
                    .is_some_and(|route_table_id| route_table_ids.contains(route_table_id))
            })
            .count();

        let next_hop_kind_by_id = self
            .next_hops
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| record.private_network_id == *private_network_id)
            .map(|record| (record.id, record.kind))
            .collect::<BTreeMap<_, _>>();

        let private_routes = self
            .private_routes
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| record.private_network_id == *private_network_id)
            .collect::<Vec<_>>();
        let private_route_count = private_routes.len();
        let private_route_ids = private_routes
            .iter()
            .map(|record| record.id.clone())
            .collect::<HashSet<_>>();

        let service_connect_attachments = self
            .service_connect_attachments
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| record.private_network_id == *private_network_id)
            .filter(|record| {
                route_table_ids.contains(&record.route_table_id)
                    && private_route_ids.contains(&record.private_route_id)
            })
            .collect::<Vec<_>>();
        let service_connect_attachment_count = service_connect_attachments.len();
        let service_connect_route_ids = service_connect_attachments
            .iter()
            .map(|record| record.private_route_id.clone())
            .collect::<HashSet<_>>();

        let ready_private_route_count = private_routes
            .iter()
            .filter(|record| route_table_ids.contains(&record.route_table_id))
            .filter(|record| {
                match next_hop_kind_by_id
                    .get(&record.next_hop_id)
                    .map(String::as_str)
                {
                    Some("local") | Some("ip_address") => true,
                    Some("service_identity") => service_connect_route_ids.contains(&record.id),
                    _ => false,
                }
            })
            .count();

        let nat_gateway_count = collect_active_values(self.nat_gateways.list().await?)
            .into_iter()
            .filter(|record| record.private_network_id == *private_network_id)
            .filter(|record| {
                topology_attachment_is_bound(&record.route_table_ids, &route_table_ids)
            })
            .count();
        let transit_attachment_count =
            collect_active_values(self.transit_attachments.list().await?)
                .into_iter()
                .filter(|record| record.private_network_id == *private_network_id)
                .filter(|record| {
                    topology_attachment_is_bound(&record.route_table_ids, &route_table_ids)
                })
                .count();
        let vpn_connection_count = collect_active_values(self.vpn_connections.list().await?)
            .into_iter()
            .filter(|record| record.private_network_id == *private_network_id)
            .filter(|record| {
                topology_attachment_is_bound(&record.route_table_ids, &route_table_ids)
            })
            .count();
        let peering_connection_count =
            collect_active_values(self.peering_connections.list().await?)
                .into_iter()
                .filter(|record| record.private_network_id == *private_network_id)
                .filter(|record| {
                    topology_attachment_is_bound(&record.route_table_ids, &route_table_ids)
                })
                .count();

        let mut missing_requirements = Vec::new();
        if subnet_count == 0 {
            missing_requirements.push(String::from("no subnets exist"));
        }
        if route_table_count == 0 {
            missing_requirements.push(String::from("no route tables exist"));
        }
        if subnets_with_route_table_count == 0 {
            missing_requirements.push(String::from("no subnets are associated with route tables"));
        }
        if ready_private_route_count == 0
            && transit_attachment_count == 0
            && vpn_connection_count == 0
            && peering_connection_count == 0
        {
            missing_requirements.push(String::from(
                "no reachable private routes or transit/vpn/peering attachments exist",
            ));
        }

        Ok(PrivateNetworkTopologyReadiness {
            ready: missing_requirements.is_empty(),
            subnet_count,
            subnets_with_route_table_count,
            route_table_count,
            private_route_count,
            ready_private_route_count,
            service_connect_attachment_count,
            nat_gateway_count,
            transit_attachment_count,
            vpn_connection_count,
            peering_connection_count,
            missing_requirements,
        })
    }

    async fn capture_private_network_topology_snapshot(
        &self,
        private_network_id: &PrivateNetworkId,
    ) -> Result<RoutePrivateNetworkEvaluationSnapshot> {
        let network = self
            .validate_private_network_attachment(private_network_id)
            .await?;
        let topology = self
            .private_network_topology_readiness(private_network_id)
            .await?;
        let rationale = private_network_topology_rationale(&network.name, &network.cidr, &topology);
        Ok(RoutePrivateNetworkEvaluationSnapshot {
            private_network_id: private_network_id.clone(),
            private_network_name: network.name,
            cidr: network.cidr,
            topology,
            rationale,
        })
    }

    async fn capture_route_publication_evaluation(
        &self,
        hostname: &str,
        protocol: Protocol,
        publication: &EdgePublication,
    ) -> Result<RoutePublicationEvaluationSnapshot> {
        validate_route_publication_shape(protocol, publication)?;

        let dns_binding = if let Some(binding) = publication.dns_binding.as_ref() {
            let zone = self
                .validate_route_zone_binding(&binding.zone_id, hostname)
                .await?;
            let rationale = if zone.verified {
                format!(
                    "hostname {hostname} is covered by verified managed zone {}",
                    zone.domain
                )
            } else {
                format!(
                    "hostname {hostname} is covered by managed zone {} but verification is still pending",
                    zone.domain
                )
            };
            Some(RouteDnsBindingEvaluationSnapshot {
                zone_id: binding.zone_id.clone(),
                domain: zone.domain,
                verified: zone.verified,
                rationale,
            })
        } else {
            None
        };

        let security_policy = if let Some(attachment) = publication.security_policy.as_ref() {
            let profile = self
                .validate_inspection_profile_attachment(&attachment.inspection_profile_id)
                .await?;
            Some(RouteSecurityPolicyEvaluationSnapshot {
                inspection_profile_id: attachment.inspection_profile_id.clone(),
                inspection_profile_name: profile.name.clone(),
                blocked_countries: profile.blocked_countries,
                min_waf_score: profile.min_waf_score,
                max_bot_score: profile.max_bot_score,
                ddos_mode: profile.ddos_mode.clone(),
                rationale: format!(
                    "protocol {} captured inspection profile {} for durable exposure evaluation",
                    protocol_name(protocol),
                    profile.name
                ),
            })
        } else {
            None
        };

        let private_network = if let Some(attachment) = publication.private_network.as_ref() {
            let snapshot = self
                .capture_private_network_topology_snapshot(&attachment.private_network_id)
                .await?;
            if !snapshot.topology.ready {
                return Err(PlatformError::conflict(
                    "private_network topology is not ready for private exposure",
                )
                .with_detail(snapshot.rationale.clone()));
            }
            Some(snapshot)
        } else {
            None
        };

        let mut evidence = Vec::new();
        if let Some(snapshot) = dns_binding.as_ref() {
            evidence.push(snapshot.rationale.clone());
        }
        if let Some(snapshot) = security_policy.as_ref() {
            evidence.push(snapshot.rationale.clone());
        }
        if let Some(snapshot) = private_network.as_ref() {
            evidence.push(snapshot.rationale.clone());
        }

        let rationale = if evidence.is_empty() {
            format!(
                "{} exposure admitted without auxiliary attachment snapshots",
                publication.exposure.as_str()
            )
        } else {
            format!(
                "{} exposure admitted with {}",
                publication.exposure.as_str(),
                evidence.join("; ")
            )
        };

        Ok(RoutePublicationEvaluationSnapshot {
            captured_at: OffsetDateTime::now_utc(),
            admitted: true,
            rationale,
            dns_binding,
            security_policy,
            private_network,
        })
    }

    async fn evaluate_attached_edge_policy(
        &self,
        route: &RouteRecord,
        request: &EvaluateRouteRequest,
    ) -> Result<Option<IngressEdgePolicyDecisionAudit>> {
        let Some(security_policy) = route.publication.security_policy.as_ref() else {
            return Ok(None);
        };
        if !supports_edge_security_policy(route.protocol) {
            return Err(PlatformError::conflict(
                "security_policy attachment is not supported for this route protocol",
            ));
        }

        let profile = self
            .validate_inspection_profile_attachment(&security_policy.inspection_profile_id)
            .await?;
        let request_path = request
            .request_path
            .as_deref()
            .map(normalize_edge_request_path)
            .transpose()?
            .unwrap_or_else(default_edge_request_path);
        let source_country = request
            .source_country
            .as_deref()
            .map(normalize_country_code)
            .transpose()?;
        let ddos_suspected = request.ddos_suspected.unwrap_or(false);
        let ddos_mode = profile.ddos_mode.to_ascii_lowercase();

        let (verdict, reason) = if let Some(country) = source_country.as_deref()
            && profile
                .blocked_countries
                .iter()
                .any(|entry| entry.eq_ignore_ascii_case(country))
        {
            (
                String::from("deny"),
                format!("blocked by geo restriction for country {country}"),
            )
        } else if let Some(waf_score) = request.waf_score
            && waf_score < profile.min_waf_score
        {
            (
                String::from("deny"),
                format!(
                    "blocked by waf threshold {} < {}",
                    waf_score, profile.min_waf_score
                ),
            )
        } else if let Some(bot_score) = request.bot_score
            && bot_score > profile.max_bot_score
        {
            (
                String::from("deny"),
                format!(
                    "blocked by bot score {} > {}",
                    bot_score, profile.max_bot_score
                ),
            )
        } else if ddos_suspected {
            match ddos_mode.as_str() {
                "block" => (
                    String::from("deny"),
                    String::from("blocked by ddos_mode=block"),
                ),
                "mitigate" => (
                    String::from("deny"),
                    String::from("blocked for ddos mitigation"),
                ),
                _ => (
                    String::from("allow"),
                    String::from("inspection profile passed"),
                ),
            }
        } else {
            (
                String::from("allow"),
                String::from("inspection profile passed"),
            )
        };

        Ok(Some(IngressEdgePolicyDecisionAudit {
            inspection_profile_id: profile.id,
            inspection_profile_name: profile.name,
            request_path,
            verdict,
            reason,
            source_country,
            waf_score: request.waf_score,
            bot_score: request.bot_score,
            ddos_suspected,
        }))
    }

    async fn evaluate_private_network_context(
        &self,
        route: &RouteRecord,
        request: &EvaluateRouteRequest,
    ) -> Result<Option<String>> {
        if route.publication.exposure != EdgeExposureIntent::Private {
            return Ok(None);
        }

        let Some(private_network) = route.publication.private_network.as_ref() else {
            return Ok(Some(String::from(
                "private route is missing required private_network attachment",
            )));
        };

        match self
            .capture_private_network_topology_snapshot(&private_network.private_network_id)
            .await
        {
            Ok(snapshot) => {
                if !snapshot.topology.ready {
                    return Ok(Some(format!(
                        "private route attached private network topology is not ready: {}",
                        private_network_topology_not_ready_message(&snapshot.topology)
                    )));
                }
            }
            Err(error) if error.code == ErrorCode::NotFound => {
                return Ok(Some(String::from(
                    "private route attached private network does not exist",
                )));
            }
            Err(error) => return Err(error),
        }

        let Some(request_private_network_id) = request
            .private_network_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(Some(String::from(
                "private route requires private_network_id context",
            )));
        };

        let request_private_network_id =
            PrivateNetworkId::parse(request_private_network_id.to_owned()).map_err(|error| {
                PlatformError::invalid("invalid private_network_id").with_detail(error.to_string())
            })?;

        match self
            .validate_private_network_attachment(&request_private_network_id)
            .await
        {
            Ok(_) => {}
            Err(error) if error.code == ErrorCode::NotFound => {
                return Ok(Some(String::from(
                    "private_network_id does not reference an existing private network",
                )));
            }
            Err(error) => return Err(error),
        }

        if request_private_network_id != private_network.private_network_id {
            return Ok(Some(String::from(
                "private_network_id does not match route private network",
            )));
        }

        Ok(None)
    }

    async fn create_route(
        &self,
        request: CreateRouteRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let change_request_id = request.change_request_id.as_deref().ok_or_else(|| {
            PlatformError::conflict("change_request_id is required for ingress route mutations")
        })?;
        let change_request_id = self.validate_governance_gate(change_request_id).await?;
        let change_request_id_text = change_request_id.to_string();
        let id = RouteId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate route id").with_detail(error.to_string())
        })?;
        let hostname = canonicalize_hostname(&request.hostname)?;
        let protocol = parse_protocol(&request.protocol)?;
        let publication = build_publication(request.publication.clone())?;
        let publication_evaluation = self
            .capture_route_publication_evaluation(&hostname, protocol, &publication)
            .await?;
        let mut backends = build_backends(&request)?;
        if backends.is_empty() {
            return Err(PlatformError::invalid(
                "route requires at least one backend target",
            ));
        }
        for backend in &mut backends {
            backend.target = canonicalize_backend_target(&backend.target)?;
        }
        let sticky_policy = request.sticky_session_policy.unwrap_or_else(|| {
            if request.sticky_sessions {
                StickySessionPolicy {
                    enabled: true,
                    ..StickySessionPolicy::default()
                }
            } else {
                StickySessionPolicy::default()
            }
        });

        let mut route = RouteRecord {
            id: id.clone(),
            hostname: hostname.clone(),
            target: backends
                .first()
                .map(|backend| backend.target.clone())
                .unwrap_or_default(),
            protocol,
            tls_mode: normalize_tls_mode(&request.tls_mode),
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
            publication,
            publication_evaluation: Some(publication_evaluation.clone()),
            backends,
            health_check: request.health_check.unwrap_or_default(),
            retry_policy: request.retry_policy.unwrap_or_default(),
            circuit_breaker: request.circuit_breaker.unwrap_or_default(),
            timeout_policy: request.timeout_policy.unwrap_or_default(),
            header_policy: request.header_policy.unwrap_or_default(),
            compression_policy: request.compression_policy.unwrap_or_default(),
            rate_limit_policy: request.rate_limit_policy.unwrap_or_default(),
            sticky_session_policy: sticky_policy,
            service_identity_policy: request.service_identity_policy.unwrap_or_default(),
            steering_policy: request.steering_policy.unwrap_or_default(),
            policy_state: RoutePolicyState::default(),
        };
        let mutation_digest = route_mutation_digest(&route, &change_request_id_text)?;
        let change_authorization = Self::governance_change_authorization(
            context,
            change_request_id.clone(),
            mutation_digest.clone(),
        );
        change_authorization.annotate_metadata(&mut route.metadata, "ingress.mutation_digest");
        route.change_authorization = Some(change_authorization.clone());
        validate_route_record(&route)?;
        self.routes.create(id.as_str(), route.clone()).await?;
        let mut details = serde_json::json!({
            "hostname": hostname,
            "protocol": route.protocol,
            "backend_count": route.backends.len(),
            "change_request_id": change_request_id_text,
            "mutation_digest": mutation_digest,
            "exposure": route.publication.exposure.as_str(),
            "publication_target_count": route.publication.targets.len(),
            "draining_publication_target_count": route
                .publication
                .targets
                .iter()
                .filter(|target| target.drain)
                .count(),
            "dns_zone_id": route
                .publication
                .dns_binding
                .as_ref()
                .map(|binding| binding.zone_id.to_string()),
            "inspection_profile_id": route
                .publication
                .security_policy
                .as_ref()
                .map(|policy| policy.inspection_profile_id.to_string()),
            "private_network_id": route
                .publication
                .private_network
                .as_ref()
                .map(|private_network| private_network.private_network_id.to_string()),
            "publication_target_ids": route
                .publication
                .targets
                .iter()
                .map(|target| target.id.to_string())
                .collect::<Vec<_>>(),
            "publication_target_cells": route
                .publication
                .targets
                .iter()
                .map(|target| target.cell.clone())
                .collect::<Vec<_>>(),
            "publication_target_regions": route
                .publication
                .targets
                .iter()
                .map(|target| target.region.clone())
                .collect::<Vec<_>>(),
            "publication_target_failover_groups": route
                .publication
                .targets
                .iter()
                .filter_map(|target| target.failover_group.clone())
                .collect::<Vec<_>>(),
            "publication_evaluation": route.publication_evaluation.clone(),
            "steering_locality_mode": route.steering_policy.locality_mode,
            "steering_locality_fallback_to_any_healthy": route
                .steering_policy
                .fallback_to_any_healthy,
            "steering_canary_traffic_percent": route
                .steering_policy
                .canary
                .traffic_percent,
        });
        append_change_authorization_details(&mut details, &change_authorization);
        self.append_event(
            "ingress.route.created.v1",
            "route",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &route)
    }

    async fn validate_governance_gate(&self, change_request_id: &str) -> Result<ChangeRequestId> {
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
        let state = stored.value.state.trim().to_ascii_lowercase();
        if state != "approved" && state != "applied" {
            return Err(PlatformError::conflict(
                "change_request_id is not approved/applied in governance",
            ));
        }
        Ok(change_request_id)
    }

    fn request_governance_provenance(context: &RequestContext) -> GovernanceRequestProvenance {
        GovernanceRequestProvenance {
            authenticated_actor: context
                .principal
                .as_ref()
                .map(|principal| principal.subject.clone())
                .or_else(|| context.actor.clone())
                .unwrap_or_else(|| String::from("system")),
            principal: context.principal.clone(),
            correlation_id: context.correlation_id.clone(),
            request_id: context.request_id.clone(),
        }
    }

    fn governance_change_authorization(
        context: &RequestContext,
        change_request_id: ChangeRequestId,
        mutation_digest: String,
    ) -> GovernanceChangeAuthorization {
        GovernanceChangeAuthorization {
            change_request_id,
            mutation_digest,
            authorized_at: OffsetDateTime::now_utc(),
            provenance: Self::request_governance_provenance(context),
        }
    }

    async fn resolve_route(&self, request: ResolveRouteRequest) -> Result<http::Response<ApiBody>> {
        let hostname = canonicalize_hostname(&request.hostname)?;
        let route = self
            .routes
            .list()
            .await?
            .into_iter()
            .find(|(_, stored)| !stored.deleted && stored.value.hostname == hostname)
            .map(|(_, stored)| stored.value);
        json_response(StatusCode::OK, &route)
    }

    async fn evaluate_route(
        &self,
        request: EvaluateRouteRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let result = self.evaluate_route_internal(request, context).await?;
        json_response(StatusCode::OK, &result)
    }

    async fn evaluate_route_internal(
        &self,
        request: EvaluateRouteRequest,
        context: &RequestContext,
    ) -> Result<EvaluateRouteResponse> {
        let hostname = canonicalize_hostname(&request.hostname)?;
        let protocol = request
            .protocol
            .as_deref()
            .map(parse_protocol)
            .transpose()?;
        let candidate = self.routes.list().await?.into_iter().find(|(_, stored)| {
            !stored.deleted
                && stored.value.hostname == hostname
                && protocol
                    .as_ref()
                    .is_none_or(|required| *required == stored.value.protocol)
        });

        let Some((route_key, stored)) = candidate else {
            self.append_decision_audit(
                None,
                &hostname,
                "deny",
                "no matching route",
                None,
                None,
                request.source_identity.clone(),
                request.client_ip.clone(),
                None,
                SteeringAuditEvidence::default(),
            )
            .await?;
            return Ok(EvaluateRouteResponse {
                admitted: false,
                route_id: None,
                selected_backend_id: None,
                selected_backend: None,
                reason: String::from("no matching route"),
                circuit_state: String::from("n/a"),
                timeout_policy: None,
                retry_policy: None,
                sticky_cookie_name: None,
            });
        };

        let mut route = stored.value;
        let now = OffsetDateTime::now_utc();
        let state_changed =
            advance_circuit_window(&mut route.policy_state, &route.circuit_breaker, now);
        if state_changed {
            self.routes
                .upsert(&route_key, route.clone(), Some(stored.version))
                .await?;
        }

        if let Some(reason) = check_identity_policy(
            &route.service_identity_policy,
            request.source_identity.as_deref(),
        ) {
            self.append_decision_audit(
                Some(route.id.clone()),
                &hostname,
                "deny",
                &reason,
                None,
                None,
                request.source_identity.clone(),
                request.client_ip.clone(),
                None,
                SteeringAuditEvidence::default(),
            )
            .await?;
            return Ok(EvaluateRouteResponse {
                admitted: false,
                route_id: Some(route.id.to_string()),
                selected_backend_id: None,
                selected_backend: None,
                reason,
                circuit_state: format!("{:?}", route.policy_state.circuit_state)
                    .to_ascii_lowercase(),
                timeout_policy: Some(route.timeout_policy),
                retry_policy: Some(route.retry_policy),
                sticky_cookie_name: if route.sticky_session_policy.enabled {
                    Some(route.sticky_session_policy.cookie_name)
                } else {
                    None
                },
            });
        }

        if let Some(reason) = self
            .evaluate_private_network_context(&route, &request)
            .await?
        {
            self.append_decision_audit(
                Some(route.id.clone()),
                &hostname,
                "deny",
                &reason,
                None,
                None,
                request.source_identity.clone(),
                request.client_ip.clone(),
                None,
                SteeringAuditEvidence::default(),
            )
            .await?;
            return Ok(EvaluateRouteResponse {
                admitted: false,
                route_id: Some(route.id.to_string()),
                selected_backend_id: None,
                selected_backend: None,
                reason,
                circuit_state: format!("{:?}", route.policy_state.circuit_state)
                    .to_ascii_lowercase(),
                timeout_policy: Some(route.timeout_policy),
                retry_policy: Some(route.retry_policy),
                sticky_cookie_name: if route.sticky_session_policy.enabled {
                    Some(route.sticky_session_policy.cookie_name)
                } else {
                    None
                },
            });
        }

        if route_has_only_draining_publication_targets(&route) {
            let reason = String::from("route has no active publication targets");
            self.append_decision_audit(
                Some(route.id.clone()),
                &hostname,
                "deny",
                &reason,
                None,
                None,
                request.source_identity.clone(),
                request.client_ip.clone(),
                None,
                SteeringAuditEvidence::default(),
            )
            .await?;
            return Ok(EvaluateRouteResponse {
                admitted: false,
                route_id: Some(route.id.to_string()),
                selected_backend_id: None,
                selected_backend: None,
                reason,
                circuit_state: format!("{:?}", route.policy_state.circuit_state)
                    .to_ascii_lowercase(),
                timeout_policy: Some(route.timeout_policy),
                retry_policy: Some(route.retry_policy),
                sticky_cookie_name: if route.sticky_session_policy.enabled {
                    Some(route.sticky_session_policy.cookie_name)
                } else {
                    None
                },
            });
        }

        if route.policy_state.circuit_state == CircuitState::Open {
            let reason = String::from("route circuit breaker is open");
            self.append_decision_audit(
                Some(route.id.clone()),
                &hostname,
                "deny",
                &reason,
                None,
                None,
                request.source_identity.clone(),
                request.client_ip.clone(),
                None,
                SteeringAuditEvidence::default(),
            )
            .await?;
            return Ok(EvaluateRouteResponse {
                admitted: false,
                route_id: Some(route.id.to_string()),
                selected_backend_id: None,
                selected_backend: None,
                reason,
                circuit_state: String::from("open"),
                timeout_policy: Some(route.timeout_policy),
                retry_policy: Some(route.retry_policy),
                sticky_cookie_name: if route.sticky_session_policy.enabled {
                    Some(route.sticky_session_policy.cookie_name)
                } else {
                    None
                },
            });
        }

        let edge_policy = self.evaluate_attached_edge_policy(&route, &request).await?;
        if let Some(edge_policy_decision) = edge_policy.as_ref()
            && edge_policy_decision.verdict == "deny"
        {
            let reason = edge_policy_decision.reason.clone();
            self.append_decision_audit(
                Some(route.id.clone()),
                &hostname,
                "deny",
                &reason,
                None,
                None,
                request.source_identity.clone(),
                request.client_ip.clone(),
                Some(edge_policy_decision.clone()),
                SteeringAuditEvidence::default(),
            )
            .await?;
            return Ok(EvaluateRouteResponse {
                admitted: false,
                route_id: Some(route.id.to_string()),
                selected_backend_id: None,
                selected_backend: None,
                reason,
                circuit_state: format!("{:?}", route.policy_state.circuit_state)
                    .to_ascii_lowercase(),
                timeout_policy: Some(route.timeout_policy),
                retry_policy: Some(route.retry_policy),
                sticky_cookie_name: if route.sticky_session_policy.enabled {
                    Some(route.sticky_session_policy.cookie_name)
                } else {
                    None
                },
            });
        }

        let limit_key = format!(
            "{}:{}",
            route.id,
            request
                .client_ip
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("global")
        );
        if !self
            .consume_rate_limit(
                &limit_key,
                &route.rate_limit_policy,
                OffsetDateTime::now_utc().unix_timestamp(),
            )
            .await
        {
            let reason = String::from("route rate limit exceeded");
            self.append_decision_audit(
                Some(route.id.clone()),
                &hostname,
                "deny",
                &reason,
                None,
                None,
                request.source_identity.clone(),
                request.client_ip.clone(),
                edge_policy.clone(),
                SteeringAuditEvidence::default(),
            )
            .await?;
            return Ok(EvaluateRouteResponse {
                admitted: false,
                route_id: Some(route.id.to_string()),
                selected_backend_id: None,
                selected_backend: None,
                reason,
                circuit_state: format!("{:?}", route.policy_state.circuit_state)
                    .to_ascii_lowercase(),
                timeout_policy: Some(route.timeout_policy),
                retry_policy: Some(route.retry_policy),
                sticky_cookie_name: if route.sticky_session_policy.enabled {
                    Some(route.sticky_session_policy.cookie_name)
                } else {
                    None
                },
            });
        }

        let (backend, steering) = match select_backend(
            &route,
            &request,
            &self.route_rr_cursor,
            context.correlation_id.as_str(),
        )
        .await?
        {
            BackendSelectionOutcome::Selected { backend, steering } => (backend, steering),
            BackendSelectionOutcome::Denied(steering) => {
                let reason = steering
                    .denial_reason
                    .clone()
                    .unwrap_or_else(|| String::from("route steering denied request"));
                self.append_decision_audit(
                    Some(route.id.clone()),
                    &hostname,
                    "deny",
                    &reason,
                    None,
                    None,
                    request.source_identity.clone(),
                    request.client_ip.clone(),
                    edge_policy.clone(),
                    steering,
                )
                .await?;
                return Ok(EvaluateRouteResponse {
                    admitted: false,
                    route_id: Some(route.id.to_string()),
                    selected_backend_id: None,
                    selected_backend: None,
                    reason,
                    circuit_state: format!("{:?}", route.policy_state.circuit_state)
                        .to_ascii_lowercase(),
                    timeout_policy: Some(route.timeout_policy),
                    retry_policy: Some(route.retry_policy),
                    sticky_cookie_name: if route.sticky_session_policy.enabled {
                        Some(route.sticky_session_policy.cookie_name)
                    } else {
                        None
                    },
                });
            }
        };

        let response = EvaluateRouteResponse {
            admitted: true,
            route_id: Some(route.id.to_string()),
            selected_backend_id: Some(backend.id.clone()),
            selected_backend: Some(backend.target.clone()),
            reason: String::from("admitted"),
            circuit_state: format!("{:?}", route.policy_state.circuit_state).to_ascii_lowercase(),
            timeout_policy: Some(route.timeout_policy.clone()),
            retry_policy: Some(route.retry_policy.clone()),
            sticky_cookie_name: if route.sticky_session_policy.enabled {
                Some(route.sticky_session_policy.cookie_name.clone())
            } else {
                None
            },
        };
        self.append_decision_audit(
            Some(route.id.clone()),
            &hostname,
            "allow",
            "matched route",
            Some(backend.target),
            Some(backend.id),
            request.source_identity.clone(),
            request.client_ip.clone(),
            edge_policy,
            steering,
        )
        .await?;
        Ok(response)
    }

    async fn report_backend_health(
        &self,
        route_id: &str,
        request: RouteHealthReportRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let updated = self
            .mutate_route(route_id, |route| {
                let Some(backend) = route
                    .backends
                    .iter_mut()
                    .find(|entry| entry.id == request.backend_id)
                else {
                    return Err(PlatformError::not_found("route backend does not exist"));
                };
                backend.healthy = request.healthy;
                backend.last_checked_at = Some(OffsetDateTime::now_utc());
                if request.healthy {
                    backend.failure_count = 0;
                } else {
                    backend.failure_count = backend.failure_count.saturating_add(1);
                }
                Ok(())
            })
            .await?;

        self.append_event(
            "ingress.backend.health_reported.v1",
            "route_backend",
            &format!("{route_id}:{}", request.backend_id),
            "updated",
            serde_json::json!({
                "healthy": request.healthy,
                "observed_latency_ms": request.observed_latency_ms,
                "message": request.message,
            }),
            context,
        )
        .await?;

        json_response(StatusCode::OK, &updated)
    }

    async fn record_circuit_event(
        &self,
        route_id: &str,
        request: RouteCircuitEventRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let updated = self
            .mutate_route(route_id, |route| {
                let now = OffsetDateTime::now_utc();
                let state = &mut route.policy_state;
                if request.success {
                    match state.circuit_state {
                        CircuitState::Closed => {
                            state.consecutive_failures = 0;
                            state.consecutive_successes = 0;
                        }
                        CircuitState::HalfOpen => {
                            state.consecutive_successes =
                                state.consecutive_successes.saturating_add(1);
                            state.consecutive_failures = 0;
                            if state.consecutive_successes
                                >= route.circuit_breaker.success_threshold
                            {
                                state.circuit_state = CircuitState::Closed;
                                state.opened_at = None;
                                state.consecutive_failures = 0;
                                state.consecutive_successes = 0;
                                state.last_transition_at = now;
                            }
                        }
                        CircuitState::Open => {}
                    }
                } else {
                    state.consecutive_successes = 0;
                    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                    if state.circuit_state == CircuitState::HalfOpen
                        || state.consecutive_failures >= route.circuit_breaker.failure_threshold
                    {
                        state.circuit_state = CircuitState::Open;
                        state.opened_at = Some(now);
                        state.last_transition_at = now;
                    }
                }
                Ok(())
            })
            .await?;

        self.append_event(
            "ingress.route.circuit_event.v1",
            "route",
            route_id,
            "updated",
            serde_json::json!({
                "success": request.success,
                "reason": request.reason,
                "state": updated.policy_state.circuit_state,
                "consecutive_failures": updated.policy_state.consecutive_failures,
                "consecutive_successes": updated.policy_state.consecutive_successes,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &updated.policy_state)
    }

    async fn mutate_route<F>(&self, route_id: &str, mutator: F) -> Result<RouteRecord>
    where
        F: FnOnce(&mut RouteRecord) -> Result<()>,
    {
        let stored = self
            .routes
            .get(route_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("route does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("route does not exist"));
        }
        let mut route = stored.value;
        mutator(&mut route)?;
        self.routes
            .upsert(route_id, route.clone(), Some(stored.version))
            .await?;
        Ok(route)
    }

    async fn consume_rate_limit(&self, key: &str, policy: &RateLimitPolicy, now_unix: i64) -> bool {
        let minute = now_unix / 60;
        {
            let mut last_cleanup = self.rate_limit_last_cleanup_minute.lock().await;
            if *last_cleanup != minute {
                let mut counters = self.rate_counters.lock().await;
                counters.retain(|_, entry| entry.window_start_minute >= minute - 1);
                *last_cleanup = minute;
            }
        }
        let mut counters = self.rate_counters.lock().await;
        let entry = counters.entry(String::from(key)).or_insert(RateCounter {
            window_start_minute: minute,
            count: 0,
        });
        if entry.window_start_minute != minute {
            entry.window_start_minute = minute;
            entry.count = 0;
        }
        let limit = policy.requests_per_minute.saturating_add(policy.burst);
        if entry.count >= limit {
            return false;
        }
        entry.count = entry.count.saturating_add(1);
        true
    }

    #[allow(clippy::too_many_arguments)]
    async fn append_decision_audit(
        &self,
        route_id: Option<RouteId>,
        hostname: &str,
        verdict: &str,
        reason: &str,
        backend: Option<String>,
        backend_id: Option<String>,
        source_identity: Option<String>,
        client_ip: Option<String>,
        edge_policy: Option<IngressEdgePolicyDecisionAudit>,
        steering: SteeringAuditEvidence,
    ) -> Result<()> {
        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate ingress flow audit id")
                .with_detail(error.to_string())
        })?;
        let entry = IngressDecisionAudit {
            id: id.clone(),
            route_id,
            hostname: hostname.to_owned(),
            verdict: verdict.to_owned(),
            reason: reason.to_owned(),
            selected_backend: backend,
            selected_backend_id: backend_id,
            source_identity,
            client_ip,
            edge_policy,
            steering_denial_reason: steering.denial_reason,
            selected_locality: steering.selected_locality,
            selected_canary_pool: steering.selected_canary_pool,
            observed_at: OffsetDateTime::now_utc(),
        };
        self.decision_audit.create(id.as_str(), entry).await?;
        Ok(())
    }

    async fn list_flow_audit(
        &self,
        query: &BTreeMap<String, String>,
    ) -> Result<http::Response<ApiBody>> {
        let verdict_filter = query.get("verdict").map(|value| value.to_ascii_lowercase());
        let route_id_filter = query.get("route_id").map(String::as_str);
        let hostname_filter = query
            .get("hostname")
            .map(|value| value.to_ascii_lowercase());
        let source_identity_filter = query
            .get("source_identity")
            .map(|value| value.to_ascii_lowercase());
        let limit = query
            .get("limit")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(200)
            .min(5_000);

        let mut values = self
            .decision_audit
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|entry| {
                verdict_filter
                    .as_ref()
                    .is_none_or(|value| entry.verdict.to_ascii_lowercase() == *value)
            })
            .filter(|entry| {
                route_id_filter.is_none_or(|value| {
                    entry
                        .route_id
                        .as_ref()
                        .map(|id| id.as_str() == value)
                        .unwrap_or(false)
                })
            })
            .filter(|entry| {
                hostname_filter
                    .as_ref()
                    .is_none_or(|value| entry.hostname.to_ascii_lowercase() == *value)
            })
            .filter(|entry| {
                source_identity_filter.as_ref().is_none_or(|value| {
                    entry
                        .source_identity
                        .as_ref()
                        .map(|candidate| candidate.to_ascii_lowercase() == *value)
                        .unwrap_or(false)
                })
            })
            .collect::<Vec<_>>();
        values.sort_by_key(|entry| entry.observed_at);
        values.reverse();
        if values.len() > limit {
            values.truncate(limit);
        }
        json_response(StatusCode::OK, &values)
    }

    async fn summarize_flow_audit(&self) -> Result<http::Response<ApiBody>> {
        let mut summary = IngressAuditSummary {
            total: 0,
            allow: 0,
            deny: 0,
        };
        for (_, stored) in self.decision_audit.list().await? {
            if stored.deleted {
                continue;
            }
            summary.total = summary.total.saturating_add(1);
            if stored.value.verdict == "allow" {
                summary.allow = summary.allow.saturating_add(1);
            } else {
                summary.deny = summary.deny.saturating_add(1);
            }
        }
        json_response(StatusCode::OK, &summary)
    }

    async fn ingress_summary(&self) -> Result<IngressSummaryResponse> {
        let routes = self
            .routes
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let total_routes = routes.len();
        let total_sites = routes
            .iter()
            .map(|route| route.hostname.clone())
            .collect::<HashSet<_>>()
            .len();
        let total_backends = routes.iter().map(|route| route.backends.len()).sum();
        let total_dns_bindings = routes
            .iter()
            .filter(|route| route.publication.dns_binding.is_some())
            .count();
        let total_edge_policy_routes = routes
            .iter()
            .filter(|route| route.publication.security_policy.is_some())
            .count();
        let total_private_routes = routes
            .iter()
            .filter(|route| route.publication.exposure == EdgeExposureIntent::Private)
            .count();
        let total_publication_targets = routes
            .iter()
            .map(|route| route.publication.targets.len())
            .sum();
        let draining_publication_targets = routes
            .iter()
            .flat_map(|route| route.publication.targets.iter())
            .filter(|target| target.drain)
            .count();
        let publication_regions = routes
            .iter()
            .flat_map(|route| {
                route
                    .publication
                    .targets
                    .iter()
                    .map(|target| target.region.clone())
            })
            .collect::<HashSet<_>>()
            .len();
        let publication_cells = routes
            .iter()
            .flat_map(|route| {
                route
                    .publication
                    .targets
                    .iter()
                    .map(|target| target.cell.clone())
            })
            .collect::<HashSet<_>>()
            .len();
        let publication_failover_groups = routes
            .iter()
            .flat_map(|route| {
                route.publication.targets.iter().filter_map(|target| {
                    target
                        .failover_group
                        .as_ref()
                        .map(|value| value.to_ascii_lowercase())
                })
            })
            .collect::<HashSet<_>>()
            .len();

        let dns_entries = self.dns_zones.list().await?;
        let mut total_dns_zones = 0_usize;
        let mut dns_ready_domains = 0_usize;
        for (_, stored) in dns_entries {
            if stored.deleted {
                continue;
            }
            total_dns_zones += 1;
            if stored.value.verified {
                dns_ready_domains += 1;
            }
        }
        let dns_pending_domains = total_dns_zones.saturating_sub(dns_ready_domains);

        let total_inspection_profiles = self
            .inspection_profiles
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .count();
        let total_private_networks = self
            .private_networks
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .count();

        Ok(IngressSummaryResponse {
            total_routes,
            total_sites,
            total_backends,
            total_dns_bindings,
            total_dns_zones,
            dns_ready_domains,
            dns_pending_domains,
            total_edge_policy_routes,
            total_inspection_profiles,
            total_private_routes,
            total_private_networks,
            total_publication_targets,
            draining_publication_targets,
            publication_regions,
            publication_cells,
            publication_failover_groups,
        })
    }

    async fn exposure_evidence(&self) -> Result<ExposureEvidenceResponse> {
        let mut routes = collect_active_values(self.routes.list().await?);
        routes.sort_by(|left, right| {
            left.hostname
                .cmp(&right.hostname)
                .then_with(|| left.id.to_string().cmp(&right.id.to_string()))
        });

        let dns_zone_by_id = collect_active_values(self.dns_zones.list().await?)
            .into_iter()
            .map(|zone| (zone.id.clone(), zone))
            .collect::<BTreeMap<_, _>>();
        let inspection_profile_by_id =
            collect_active_values(self.inspection_profiles.list().await?)
                .into_iter()
                .map(|profile| (profile.id.clone(), profile))
                .collect::<BTreeMap<_, _>>();
        let private_networks = collect_active_values(self.private_networks.list().await?);
        let mut private_network_topology_by_id = BTreeMap::new();
        for record in &private_networks {
            let topology = self.private_network_topology_readiness(&record.id).await?;
            private_network_topology_by_id.insert(record.id.to_string(), topology);
        }
        let mail_domains = collect_active_values(self.mail_domains.list().await?);
        let reputation_by_domain_id = collect_active_values(self.mail_reputation.list().await?)
            .into_iter()
            .map(|record| (record.domain_id.clone(), record.suspended))
            .collect::<BTreeMap<_, _>>();
        let dead_letter_counts_by_domain_id =
            dead_letter_counts(collect_active_values(self.mail_dead_letters.list().await?));
        let policy_records = collect_active_values(self.policy_records.list().await?);
        let policy_approvals = collect_active_values(self.policy_approvals.list().await?);
        let governance_change_requests =
            collect_active_values(self.governance_change_requests.list().await?);
        let governance_legal_holds =
            collect_active_values(self.governance_legal_holds.list().await?);
        let governance_audit_checkpoints =
            collect_active_values(self.governance_audit_checkpoints.list().await?);
        let abuse_quarantines = collect_active_values(self.abuse_quarantines.list().await?);
        let now = OffsetDateTime::now_utc();

        let mut public_routes = 0_usize;
        let mut private_routes = 0_usize;
        let mut routes_requiring_attention = 0_usize;
        let mut routes_with_verified_dns = 0_usize;
        let mut routes_without_active_targets = 0_usize;
        let mut routes_with_mail_risk = 0_usize;
        let mut routes_with_policy_matches = 0_usize;
        let mut matched_route_policy_ids = BTreeSet::new();
        let mut route_views = Vec::with_capacity(routes.len());

        for route in routes {
            match route.publication.exposure {
                EdgeExposureIntent::Public => public_routes += 1,
                EdgeExposureIntent::Private => private_routes += 1,
            }

            let active_publication_targets = route
                .publication
                .targets
                .iter()
                .filter(|target| !target.drain)
                .count();
            let draining_publication_targets = route
                .publication
                .targets
                .iter()
                .filter(|target| target.drain)
                .count();
            if active_publication_targets == 0 {
                routes_without_active_targets += 1;
            }

            let healthy_backends = route
                .backends
                .iter()
                .filter(|backend| backend.healthy)
                .count();
            let total_backends = route.backends.len();

            let dns = route_dns_signals(&route, &dns_zone_by_id);
            if dns.zone_verified == Some(true) {
                routes_with_verified_dns += 1;
            }

            let netsec = route_netsec_signals(
                &route,
                &inspection_profile_by_id,
                &private_network_topology_by_id,
                &abuse_quarantines,
                now,
            );
            let mail = route_mail_signals(
                &route,
                dns.zone_domain.as_deref(),
                &mail_domains,
                &reputation_by_domain_id,
                &dead_letter_counts_by_domain_id,
                &abuse_quarantines,
                now,
            );
            let policy = route_policy_signals(&route, &dns, &netsec, &policy_records);
            for policy_id in &policy.matched_policy_ids {
                matched_route_policy_ids.insert(policy_id.clone());
            }
            if policy.matched_policies > 0 {
                routes_with_policy_matches += 1;
            }

            let mut attention_reasons = exposure_attention_reasons(&route, &dns, &netsec, &mail);
            if active_publication_targets == 0 {
                attention_reasons.push(if route.publication.targets.is_empty() {
                    String::from("route has no publication targets")
                } else {
                    String::from("all publication targets are draining")
                });
            }
            if healthy_backends == 0 {
                attention_reasons.push(String::from("all route backends are unhealthy"));
            }
            if !attention_reasons.is_empty() {
                routes_requiring_attention += 1;
            }
            if route_has_mail_risk(&mail) {
                routes_with_mail_risk += 1;
            }

            route_views.push(ExposureEvidenceRoute {
                route_id: route.id.to_string(),
                hostname: route.hostname.clone(),
                protocol: protocol_name(route.protocol).to_owned(),
                exposure: route.publication.exposure.as_str().to_owned(),
                active_publication_targets,
                draining_publication_targets,
                healthy_backends,
                total_backends,
                circuit_state: format!("{:?}", route.policy_state.circuit_state)
                    .to_ascii_lowercase(),
                dns,
                netsec,
                mail,
                policy,
                attention_reasons,
            });
        }

        let total_policies = policy_records.len();
        let allow_policies = policy_records
            .iter()
            .filter(|record| record.effect == "allow")
            .count();
        let deny_policies = policy_records
            .iter()
            .filter(|record| record.effect == "deny")
            .count();
        let pending_policy_approvals = policy_approvals
            .iter()
            .filter(|approval| !approval.approved)
            .count();

        let total_change_requests = governance_change_requests.len();
        let pending_change_requests = governance_change_requests
            .iter()
            .filter(|record| record.state == "pending")
            .count();
        let approved_change_requests = governance_change_requests
            .iter()
            .filter(|record| record.state == "approved")
            .count();
        let applied_change_requests = governance_change_requests
            .iter()
            .filter(|record| record.state == "applied")
            .count();
        let active_legal_holds = governance_legal_holds
            .iter()
            .filter(|record| record.active)
            .count();
        let latest_checkpoint_at = governance_audit_checkpoints
            .iter()
            .map(|record| record.recorded_at)
            .max();

        Ok(ExposureEvidenceResponse {
            generated_at: now,
            summary: ExposureEvidenceSummary {
                total_routes: route_views.len(),
                public_routes,
                private_routes,
                routes_requiring_attention,
                routes_with_verified_dns,
                routes_without_active_targets,
                routes_with_mail_risk,
                routes_with_policy_matches,
            },
            routes: route_views,
            policy: ExposureEvidencePolicySignals {
                total_policies,
                allow_policies,
                deny_policies,
                matched_route_policies: matched_route_policy_ids.len(),
                total_approvals: policy_approvals.len(),
                pending_approvals: pending_policy_approvals,
            },
            governance: ExposureEvidenceGovernanceSignals {
                total_change_requests,
                pending_change_requests,
                approved_change_requests,
                applied_change_requests,
                active_legal_holds,
                audit_checkpoints: governance_audit_checkpoints.len(),
                latest_checkpoint_at,
            },
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
                    PlatformError::unavailable("failed to allocate ingress event id")
                        .with_detail(error.to_string())
                })?,
                event_type: event_type.to_owned(),
                schema_version: 1,
                source_service: String::from("ingress"),
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
        let event_id = event.header.event_id.to_string();
        let _ = self
            .outbox
            .enqueue("ingress.events.v1", event, Some(&event_id))
            .await?;
        Ok(())
    }
}

impl HttpService for IngressService {
    fn name(&self) -> &'static str {
        "ingress"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/ingress")];
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
            let query = parse_query(request.uri().query());
            let segments = path_segments(&path);

            match (method, segments.as_slice()) {
                (Method::GET, ["ingress"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                    }),
                )
                .map(Some),
                (Method::GET, ["ingress", "routes"]) => {
                    let values = self
                        .routes
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["ingress", "routes", route_id]) => {
                    let route = self
                        .routes
                        .get(route_id)
                        .await?
                        .filter(|stored| !stored.deleted)
                        .map(|stored| stored.value);
                    json_response(StatusCode::OK, &route).map(Some)
                }
                (Method::POST, ["ingress", "routes"]) => {
                    let body: CreateRouteRequest = parse_json(request).await?;
                    self.create_route(body, &context).await.map(Some)
                }
                (Method::POST, ["ingress", "routes", route_id, "health-report"]) => {
                    let body: RouteHealthReportRequest = parse_json(request).await?;
                    self.report_backend_health(route_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["ingress", "routes", route_id, "circuit-event"]) => {
                    let body: RouteCircuitEventRequest = parse_json(request).await?;
                    self.record_circuit_event(route_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["ingress", "resolve"]) => {
                    let body: ResolveRouteRequest = parse_json(request).await?;
                    self.resolve_route(body).await.map(Some)
                }
                (Method::POST, ["ingress", "evaluate"]) => {
                    let body: EvaluateRouteRequest = parse_json(request).await?;
                    self.evaluate_route(body, &context).await.map(Some)
                }
                (Method::GET, ["ingress", "flow-audit"]) => {
                    self.list_flow_audit(&query).await.map(Some)
                }
                (Method::GET, ["ingress", "flow-audit", "summary"]) => {
                    self.summarize_flow_audit().await.map(Some)
                }
                (Method::GET, ["ingress", "summary"]) => {
                    let summary = self.ingress_summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["ingress", "exposure-evidence"]) => {
                    let evidence = self.exposure_evidence().await?;
                    json_response(StatusCode::OK, &evidence).map(Some)
                }
                (Method::GET, ["ingress", "outbox"]) => {
                    let messages = self.outbox.list_all().await?;
                    json_response(StatusCode::OK, &messages).map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn normalize_tls_mode(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "passthrough" | "offload" | "redirect_https" | "strict_https" => normalized,
        _ => String::from("redirect_https"),
    }
}

fn parse_protocol(value: &str) -> Result<Protocol> {
    let protocol = match value.trim().to_ascii_lowercase().as_str() {
        "http" => Protocol::Http,
        "https" => Protocol::Https,
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "websocket" => Protocol::WebSocket,
        "grpc" => Protocol::Grpc,
        _ => {
            return Err(PlatformError::invalid(
                "protocol must be one of http, https, tcp, udp, websocket, or grpc",
            ));
        }
    };
    Ok(protocol)
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Http => "http",
        Protocol::Https => "https",
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::WebSocket => "websocket",
        Protocol::Grpc => "grpc",
    }
}

fn topology_attachment_is_bound(
    route_table_ids: &[String],
    known_route_table_ids: &HashSet<String>,
) -> bool {
    route_table_ids
        .iter()
        .any(|route_table_id| known_route_table_ids.contains(route_table_id))
}

fn private_network_topology_not_ready_message(
    topology: &PrivateNetworkTopologyReadiness,
) -> String {
    if topology.missing_requirements.is_empty() {
        return String::from("topology is ready");
    }
    topology.missing_requirements.join("; ")
}

fn private_network_topology_rationale(
    private_network_name: &str,
    cidr: &str,
    topology: &PrivateNetworkTopologyReadiness,
) -> String {
    if topology.ready {
        let external_attachment_count = topology.transit_attachment_count
            + topology.vpn_connection_count
            + topology.peering_connection_count;
        return format!(
            "private exposure anchored to private network {private_network_name} ({cidr}); topology is ready via {} routed subnets, {} ready private routes, {} service-connect attachments, and {} transit/vpn/peering attachments",
            topology.subnets_with_route_table_count,
            topology.ready_private_route_count,
            topology.service_connect_attachment_count,
            external_attachment_count,
        );
    }

    format!(
        "private exposure anchored to private network {private_network_name} ({cidr}); topology is not ready: {}",
        private_network_topology_not_ready_message(topology)
    )
}

fn canonicalize_backend_target(target: &str) -> Result<String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid("backend target may not be empty"));
    }
    let lowered = trimmed.to_ascii_lowercase();
    if !(lowered.starts_with("http://")
        || lowered.starts_with("https://")
        || lowered.starts_with("service://")
        || lowered.starts_with("tcp://"))
    {
        return Err(PlatformError::invalid(
            "backend target must start with http://, https://, service://, or tcp://",
        ));
    }
    Ok(trimmed.to_owned())
}

fn build_backends(request: &CreateRouteRequest) -> Result<Vec<RouteBackend>> {
    let mut backends = request
        .backends
        .iter()
        .enumerate()
        .map(|(index, backend)| RouteBackend {
            id: format!("backend-{}", index + 1),
            target: backend.target.clone(),
            weight: backend.weight.unwrap_or(1).max(1),
            region: normalize_optional_backend_location(backend.region.clone()),
            cell: normalize_optional_backend_location(backend.cell.clone()),
            canary: backend.canary,
            healthy: true,
            failure_count: 0,
            last_checked_at: None,
        })
        .collect::<Vec<_>>();
    if backends.is_empty()
        && let Some(target) = &request.target
        && !target.trim().is_empty()
    {
        backends.push(RouteBackend {
            id: String::from("backend-1"),
            target: target.clone(),
            weight: 1,
            region: None,
            cell: None,
            canary: false,
            healthy: true,
            failure_count: 0,
            last_checked_at: None,
        });
    }
    if request.sticky_sessions && backends.len() < 2 {
        return Err(PlatformError::invalid(
            "sticky_sessions requires at least two backends",
        ));
    }
    Ok(backends)
}

fn build_publication(request: Option<CreateRoutePublicationRequest>) -> Result<EdgePublication> {
    let Some(request) = request else {
        return Ok(EdgePublication::default());
    };
    let exposure = parse_edge_exposure_intent(request.exposure.as_deref().unwrap_or("public"))?;
    let dns_binding = request
        .dns_binding
        .map(|binding| {
            let zone_id = ZoneId::parse(binding.zone_id.trim().to_owned()).map_err(|error| {
                PlatformError::invalid("invalid zone_id").with_detail(error.to_string())
            })?;
            Ok(EdgeDnsBinding { zone_id })
        })
        .transpose()?;
    let security_policy = request
        .security_policy
        .map(|attachment| {
            let inspection_profile_id = PolicyId::parse(
                attachment.inspection_profile_id.trim().to_owned(),
            )
            .map_err(|error| {
                PlatformError::invalid("invalid inspection_profile_id")
                    .with_detail(error.to_string())
            })?;
            Ok(EdgeSecurityPolicyAttachment {
                inspection_profile_id,
            })
        })
        .transpose()?;
    let private_network = request
        .private_network
        .map(|attachment| {
            let private_network_id = PrivateNetworkId::parse(
                attachment.private_network_id.trim().to_owned(),
            )
            .map_err(|error| {
                PlatformError::invalid("invalid private_network_id").with_detail(error.to_string())
            })?;
            Ok(EdgePrivateNetworkAttachment { private_network_id })
        })
        .transpose()?;
    let targets = request
        .targets
        .into_iter()
        .map(build_publication_target)
        .collect::<Result<Vec<_>>>()?;
    Ok(EdgePublication {
        exposure,
        dns_binding,
        security_policy,
        private_network,
        targets,
    })
}

fn build_publication_target(
    request: CreateRoutePublicationTargetRequest,
) -> Result<EdgePublicationTarget> {
    let id = EdgePublicationTargetId::generate().map_err(|error| {
        PlatformError::unavailable("failed to allocate publication target id")
            .with_detail(error.to_string())
    })?;
    Ok(EdgePublicationTarget {
        id,
        cell: normalize_required_publication_target_field("cell", &request.cell)?,
        region: normalize_required_publication_target_field("region", &request.region)?,
        failover_group: normalize_optional_publication_target_field(request.failover_group),
        drain: request.drain,
        tls_owner: normalize_required_publication_target_field("tls_owner", &request.tls_owner)?,
    })
}

fn normalize_required_publication_target_field(field: &str, value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(format!(
            "publication target {field} may not be empty"
        )));
    }
    Ok(normalized.to_owned())
}

fn normalize_optional_publication_target_field(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn normalize_optional_backend_location(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn parse_edge_exposure_intent(value: &str) -> Result<EdgeExposureIntent> {
    match value.trim().to_ascii_lowercase().as_str() {
        "public" => Ok(EdgeExposureIntent::Public),
        "private" => Ok(EdgeExposureIntent::Private),
        _ => Err(PlatformError::invalid(
            "publication exposure must be one of public or private",
        )),
    }
}

fn validate_route_publication_shape(
    protocol: Protocol,
    publication: &EdgePublication,
) -> Result<()> {
    if publication.exposure == EdgeExposureIntent::Private && publication.private_network.is_none()
    {
        return Err(PlatformError::invalid(
            "private exposure routes must attach private_network",
        ));
    }
    if publication.exposure == EdgeExposureIntent::Private && publication.dns_binding.is_some() {
        return Err(PlatformError::invalid(
            "private exposure routes may not attach dns_binding",
        ));
    }
    if publication.exposure == EdgeExposureIntent::Private && publication.security_policy.is_some()
    {
        return Err(PlatformError::invalid(
            "private exposure routes may not attach security_policy",
        ));
    }
    if publication.exposure == EdgeExposureIntent::Public && publication.private_network.is_some() {
        return Err(PlatformError::invalid(
            "public exposure routes may not attach private_network",
        ));
    }
    if publication.security_policy.is_some() && !supports_edge_security_policy(protocol) {
        return Err(PlatformError::invalid(
            "security_policy requires protocol http, https, websocket, or grpc",
        ));
    }
    let mut target_ids = HashSet::new();
    let mut placements = HashSet::new();
    for target in &publication.targets {
        if target.cell.trim().is_empty() {
            return Err(PlatformError::invalid(
                "publication target cell may not be empty",
            ));
        }
        if target.region.trim().is_empty() {
            return Err(PlatformError::invalid(
                "publication target region may not be empty",
            ));
        }
        if target.tls_owner.trim().is_empty() {
            return Err(PlatformError::invalid(
                "publication target tls_owner may not be empty",
            ));
        }
        if !target_ids.insert(target.id.as_str()) {
            return Err(PlatformError::invalid(
                "publication target ids must be unique",
            ));
        }
        if !placements.insert((
            target.cell.to_ascii_lowercase(),
            target.region.to_ascii_lowercase(),
            target
                .failover_group
                .as_ref()
                .map(|value| value.to_ascii_lowercase()),
        )) {
            return Err(PlatformError::invalid(
                "publication targets must be unique per cell, region, and failover_group",
            ));
        }
    }
    Ok(())
}

fn supports_edge_security_policy(protocol: Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Http | Protocol::Https | Protocol::WebSocket | Protocol::Grpc
    )
}

fn normalize_edge_request_path(value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() || !normalized.starts_with('/') {
        return Err(PlatformError::invalid(
            "request_path must be an absolute path when evaluating security_policy",
        ));
    }
    Ok(normalized.to_owned())
}

fn normalize_country_code(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_uppercase();
    if normalized.len() != 2
        || !normalized
            .chars()
            .all(|character| character.is_ascii_uppercase())
    {
        return Err(PlatformError::invalid(
            "source_country must be a two-letter ISO-3166 alpha-2 code",
        ));
    }
    Ok(normalized)
}

fn route_has_only_draining_publication_targets(route: &RouteRecord) -> bool {
    !route.publication.targets.is_empty()
        && route.publication.targets.iter().all(|target| target.drain)
}

fn collect_active_values<T>(records: Vec<(String, StoredDocument<T>)>) -> Vec<T> {
    let mut active = BTreeMap::new();
    for (key, record) in records {
        if !record.deleted {
            active.insert(key, record.value);
        }
    }
    active.into_values().collect()
}

fn dead_letter_counts(dead_letters: Vec<MailDeadLetterHook>) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for record in dead_letters {
        let entry = counts.entry(record.domain_id).or_insert(0);
        *entry = (*entry).saturating_add(1);
    }
    counts
}

fn route_dns_signals(
    route: &RouteRecord,
    dns_zone_by_id: &BTreeMap<String, DnsZoneHook>,
) -> ExposureEvidenceDnsSignals {
    let Some(binding) = route.publication.dns_binding.as_ref() else {
        return ExposureEvidenceDnsSignals {
            binding_present: false,
            zone_id: None,
            zone_domain: None,
            zone_verified: None,
        };
    };

    let zone = dns_zone_by_id.get(binding.zone_id.as_str());
    ExposureEvidenceDnsSignals {
        binding_present: true,
        zone_id: Some(binding.zone_id.to_string()),
        zone_domain: zone.map(|record| record.domain.clone()),
        zone_verified: zone.map(|record| record.verified),
    }
}

fn route_netsec_signals(
    route: &RouteRecord,
    inspection_profile_by_id: &BTreeMap<String, InspectionProfileHook>,
    private_network_topology_by_id: &BTreeMap<String, PrivateNetworkTopologyReadiness>,
    abuse_quarantines: &[AbuseQuarantineHook],
    now: OffsetDateTime,
) -> ExposureEvidenceNetsecSignals {
    let inspection_profile_id = route
        .publication
        .security_policy
        .as_ref()
        .map(|attachment| attachment.inspection_profile_id.to_string());
    let inspection_profile = inspection_profile_id
        .as_ref()
        .and_then(|id| inspection_profile_by_id.get(id));
    let private_network_id = route
        .publication
        .private_network
        .as_ref()
        .map(|attachment| attachment.private_network_id.to_string());
    let private_network_topology = private_network_id
        .as_ref()
        .and_then(|id| private_network_topology_by_id.get(id))
        .cloned();

    ExposureEvidenceNetsecSignals {
        inspection_profile_id: inspection_profile_id.clone(),
        inspection_profile_name: inspection_profile.map(|record| record.name.clone()),
        inspection_profile_present: inspection_profile_id
            .as_ref()
            .is_some_and(|id| inspection_profile_by_id.contains_key(id)),
        private_network_id: private_network_id.clone(),
        private_network_present: private_network_topology.is_some(),
        private_network_ready: private_network_topology
            .as_ref()
            .map(|topology| topology.ready),
        private_network_topology,
        hostname_quarantine_active: abuse_quarantines.iter().any(|record| {
            abuse_quarantine_is_active(record, now)
                && record.deny_network
                && record.subject_kind == "hostname"
                && record.subject.eq_ignore_ascii_case(&route.hostname)
        }),
    }
}

fn route_mail_signals(
    route: &RouteRecord,
    zone_domain: Option<&str>,
    mail_domains: &[MailDomainHook],
    reputation_by_domain_id: &BTreeMap<String, bool>,
    dead_letter_counts_by_domain_id: &BTreeMap<String, usize>,
    abuse_quarantines: &[AbuseQuarantineHook],
    now: OffsetDateTime,
) -> ExposureEvidenceMailSignals {
    let route_zone_id = route
        .publication
        .dns_binding
        .as_ref()
        .map(|binding| binding.zone_id.to_string());
    let related_domains = mail_domains
        .iter()
        .filter(|domain| {
            mail_domain_matches_route(
                &route.hostname,
                route_zone_id.as_deref(),
                zone_domain,
                domain,
            )
        })
        .collect::<Vec<_>>();

    let mut related_domain_names = related_domains
        .iter()
        .map(|domain| domain.domain.clone())
        .collect::<Vec<_>>();
    related_domain_names.sort();

    let verified_domains = related_domains
        .iter()
        .filter(|domain| domain.verified)
        .count();
    let suspended_domains = related_domains
        .iter()
        .filter(|domain| {
            reputation_by_domain_id
                .get(&domain.id)
                .copied()
                .unwrap_or(false)
        })
        .count();
    let active_relay_quarantines = related_domains
        .iter()
        .filter(|domain| {
            abuse_quarantines.iter().any(|record| {
                abuse_quarantine_is_active(record, now)
                    && record.deny_mail_relay
                    && record.subject_kind == "mail_domain"
                    && (record.subject.eq_ignore_ascii_case(&domain.domain)
                        || record.subject.eq_ignore_ascii_case(&domain.id))
            })
        })
        .count();
    let dead_letter_count = related_domains
        .iter()
        .map(|domain| {
            dead_letter_counts_by_domain_id
                .get(&domain.id)
                .copied()
                .unwrap_or(0)
        })
        .sum();

    ExposureEvidenceMailSignals {
        related_domains: related_domain_names,
        verified_domains,
        suspended_domains,
        active_relay_quarantines,
        dead_letter_count,
    }
}

fn route_policy_signals(
    route: &RouteRecord,
    dns: &ExposureEvidenceDnsSignals,
    netsec: &ExposureEvidenceNetsecSignals,
    policy_records: &[PolicyRecordHook],
) -> ExposureEvidencePolicyMatchSignals {
    let route_attributes = route_policy_attributes(route, dns, netsec);
    let matched_policies = policy_records
        .iter()
        .filter(|record| policy_matches_route(record, &route_attributes))
        .collect::<Vec<_>>();
    let matched_allow_policies = matched_policies
        .iter()
        .filter(|record| record.effect == "allow")
        .count();
    let matched_deny_policies = matched_policies
        .iter()
        .filter(|record| record.effect == "deny")
        .count();
    let mut matched_policy_ids = matched_policies
        .into_iter()
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();
    matched_policy_ids.sort();

    ExposureEvidencePolicyMatchSignals {
        matched_policies: matched_policy_ids.len(),
        matched_allow_policies,
        matched_deny_policies,
        matched_policy_ids,
    }
}

fn route_policy_attributes(
    route: &RouteRecord,
    dns: &ExposureEvidenceDnsSignals,
    netsec: &ExposureEvidenceNetsecSignals,
) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::from([
        (String::from("route_id"), route.id.to_string()),
        (String::from("hostname"), route.hostname.clone()),
        (
            String::from("protocol"),
            protocol_name(route.protocol).to_owned(),
        ),
        (
            String::from("exposure"),
            route.publication.exposure.as_str().to_owned(),
        ),
        (String::from("tls_mode"), route.tls_mode.clone()),
    ]);

    if let Some(zone_id) = dns.zone_id.as_ref() {
        attributes.insert(String::from("zone_id"), zone_id.clone());
    }
    if let Some(zone_domain) = dns.zone_domain.as_ref() {
        attributes.insert(String::from("zone_domain"), zone_domain.clone());
        attributes.insert(String::from("domain"), zone_domain.clone());
    }
    if let Some(inspection_profile_id) = netsec.inspection_profile_id.as_ref() {
        attributes.insert(
            String::from("inspection_profile_id"),
            inspection_profile_id.clone(),
        );
    }
    if let Some(inspection_profile_name) = netsec.inspection_profile_name.as_ref() {
        attributes.insert(
            String::from("inspection_profile_name"),
            inspection_profile_name.clone(),
        );
    }
    if let Some(private_network_id) = netsec.private_network_id.as_ref() {
        attributes.insert(
            String::from("private_network_id"),
            private_network_id.clone(),
        );
    }
    if let Some(private_network_ready) = netsec.private_network_ready {
        attributes.insert(
            String::from("private_network_ready"),
            private_network_ready.to_string(),
        );
    }

    attributes
}

fn policy_matches_route(
    policy: &PolicyRecordHook,
    route_attributes: &BTreeMap<String, String>,
) -> bool {
    !policy.selector.is_empty()
        && policy
            .selector
            .iter()
            .all(|(key, value)| route_attributes.get(key) == Some(value))
}

fn exposure_attention_reasons(
    route: &RouteRecord,
    dns: &ExposureEvidenceDnsSignals,
    netsec: &ExposureEvidenceNetsecSignals,
    mail: &ExposureEvidenceMailSignals,
) -> Vec<String> {
    let mut reasons = Vec::new();

    if route.publication.exposure == EdgeExposureIntent::Public {
        if !dns.binding_present {
            reasons.push(String::from("public route has no dns binding"));
        }
        if route.publication.security_policy.is_none() {
            reasons.push(String::from("public route has no edge security policy"));
        }
    }
    if dns.binding_present && dns.zone_verified != Some(true) {
        reasons.push(String::from("bound dns zone is not verified"));
    }
    if route.publication.security_policy.is_some() && !netsec.inspection_profile_present {
        reasons.push(String::from("bound inspection profile is missing"));
    }
    if route.publication.private_network.is_some() && !netsec.private_network_present {
        reasons.push(String::from("bound private network is missing"));
    }
    if let Some(topology) = netsec.private_network_topology.as_ref()
        && !topology.ready
    {
        reasons.push(format!(
            "bound private network topology is not ready: {}",
            private_network_topology_not_ready_message(topology)
        ));
    }
    if netsec.hostname_quarantine_active {
        reasons.push(String::from("hostname has an active network quarantine"));
    }
    if !mail.related_domains.is_empty() && mail.verified_domains == 0 {
        reasons.push(String::from("related mail domains are not verified"));
    }
    if mail.suspended_domains > 0 {
        reasons.push(String::from("related mail domain relay is suspended"));
    }
    if mail.active_relay_quarantines > 0 {
        reasons.push(String::from(
            "related mail domain has an active relay quarantine",
        ));
    }
    if mail.dead_letter_count > 0 {
        reasons.push(String::from(
            "related mail domain has dead-lettered traffic",
        ));
    }

    reasons
}

fn route_has_mail_risk(mail: &ExposureEvidenceMailSignals) -> bool {
    mail.suspended_domains > 0
        || mail.active_relay_quarantines > 0
        || mail.dead_letter_count > 0
        || (!mail.related_domains.is_empty() && mail.verified_domains < mail.related_domains.len())
}

fn mail_domain_matches_route(
    hostname: &str,
    route_zone_id: Option<&str>,
    zone_domain: Option<&str>,
    domain: &MailDomainHook,
) -> bool {
    route_zone_id.is_some_and(|zone_id| domain.zone_id.as_deref() == Some(zone_id))
        || zone_domain.is_some_and(|value| value.eq_ignore_ascii_case(&domain.domain))
        || hostname_matches_domain(hostname, &domain.domain)
}

fn hostname_matches_domain(hostname: &str, domain: &str) -> bool {
    hostname.eq_ignore_ascii_case(domain)
        || hostname
            .to_ascii_lowercase()
            .ends_with(&format!(".{}", domain.to_ascii_lowercase()))
}

fn abuse_quarantine_is_active(record: &AbuseQuarantineHook, now: OffsetDateTime) -> bool {
    record.state == "active" && record.expires_at.is_none_or(|expires_at| expires_at > now)
}

fn append_change_authorization_details(
    details: &mut serde_json::Value,
    authorization: &GovernanceChangeAuthorization,
) {
    if let Some(object) = details.as_object_mut() {
        object.insert(
            String::from("change_authorization"),
            serde_json::json!(authorization),
        );
    }
}

fn route_mutation_digest(route: &RouteRecord, change_request_id: &str) -> Result<String> {
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "hostname": route.hostname,
        "protocol": route.protocol,
        "tls_mode": route.tls_mode,
        "backends": route.backends,
        "publication": route.publication,
        "publication_evaluation": route.publication_evaluation.as_ref().map(|snapshot| serde_json::json!({
            "admitted": snapshot.admitted,
            "rationale": snapshot.rationale,
            "dns_binding": snapshot.dns_binding,
            "security_policy": snapshot.security_policy,
            "private_network": snapshot.private_network,
        })),
        "health_check": route.health_check,
        "retry_policy": route.retry_policy,
        "circuit_breaker": route.circuit_breaker,
        "timeout_policy": route.timeout_policy,
        "header_policy": route.header_policy,
        "compression_policy": route.compression_policy,
        "rate_limit_policy": route.rate_limit_policy,
        "sticky_session_policy": route.sticky_session_policy,
        "service_identity_policy": route.service_identity_policy,
        "steering_policy": route.steering_policy,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode ingress mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(sha256_hex(&encoded))
}

fn validate_route_record(route: &RouteRecord) -> Result<()> {
    if route.hostname.trim().is_empty() {
        return Err(PlatformError::invalid("route hostname may not be empty"));
    }
    if route.backends.is_empty() {
        return Err(PlatformError::invalid(
            "route requires at least one backend",
        ));
    }
    if route.health_check.path.trim().is_empty() || !route.health_check.path.starts_with('/') {
        return Err(PlatformError::invalid(
            "health check path must be an absolute path",
        ));
    }
    if route.health_check.interval_seconds == 0 || route.health_check.timeout_ms == 0 {
        return Err(PlatformError::invalid(
            "health check interval and timeout must be greater than zero",
        ));
    }
    if route.circuit_breaker.failure_threshold == 0
        || route.circuit_breaker.success_threshold == 0
        || route.circuit_breaker.open_interval_seconds == 0
    {
        return Err(PlatformError::invalid(
            "circuit breaker thresholds must be greater than zero",
        ));
    }
    if route.timeout_policy.connect_timeout_ms == 0
        || route.timeout_policy.request_timeout_ms == 0
        || route.timeout_policy.idle_timeout_ms == 0
    {
        return Err(PlatformError::invalid(
            "timeout values must be greater than zero",
        ));
    }
    if route.sticky_session_policy.enabled
        && route.sticky_session_policy.cookie_name.trim().is_empty()
    {
        return Err(PlatformError::invalid(
            "sticky session cookie name may not be empty",
        ));
    }
    if route.steering_policy.canary.traffic_percent > 100 {
        return Err(PlatformError::invalid(
            "steering canary traffic_percent must be between 0 and 100",
        ));
    }

    let mut backend_ids = HashSet::new();
    for backend in &route.backends {
        if backend.id.trim().is_empty() {
            return Err(PlatformError::invalid("backend id may not be empty"));
        }
        if backend.target.trim().is_empty() {
            return Err(PlatformError::invalid("backend target may not be empty"));
        }
        if backend
            .region
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(PlatformError::invalid(
                "backend region may not be empty when provided",
            ));
        }
        if backend
            .cell
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(PlatformError::invalid(
                "backend cell may not be empty when provided",
            ));
        }
        if !backend_ids.insert(backend.id.as_str()) {
            return Err(PlatformError::invalid("backend ids must be unique"));
        }
    }
    validate_route_publication_shape(route.protocol, &route.publication)?;
    Ok(())
}

fn check_identity_policy(policy: &ServiceIdentityPolicy, identity: Option<&str>) -> Option<String> {
    if policy.required && identity.is_none_or(|value| value.trim().is_empty()) {
        return Some(String::from("route requires a source identity"));
    }
    if policy.require_mtls && identity.is_none_or(|value| value.trim().is_empty()) {
        return Some(String::from(
            "route requires mTLS-authenticated source identity",
        ));
    }
    if !policy.allowed_subject_prefixes.is_empty() {
        let Some(subject) = identity else {
            return Some(String::from(
                "route restricts source identities and no source identity was provided",
            ));
        };
        let allowed = policy
            .allowed_subject_prefixes
            .iter()
            .any(|prefix| subject.starts_with(prefix));
        if !allowed {
            return Some(String::from(
                "source identity is not permitted for this route",
            ));
        }
    }
    None
}

fn advance_circuit_window(
    state: &mut RoutePolicyState,
    policy: &CircuitBreakerPolicy,
    now: OffsetDateTime,
) -> bool {
    if state.circuit_state != CircuitState::Open {
        return false;
    }
    let Some(opened_at) = state.opened_at else {
        return false;
    };
    let elapsed = now.unix_timestamp() - opened_at.unix_timestamp();
    if elapsed >= i64::from(policy.open_interval_seconds) {
        state.circuit_state = CircuitState::HalfOpen;
        state.consecutive_failures = 0;
        state.consecutive_successes = 0;
        state.last_transition_at = now;
        return true;
    }
    false
}

fn normalize_optional_locality_hint(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn steering_locality_cell(cell: &str) -> String {
    format!("cell:{cell}")
}

fn steering_locality_region(region: &str) -> String {
    format!("region:{region}")
}

fn steering_locality_fallback() -> String {
    String::from("fallback:any_healthy")
}

fn steering_locality_unconstrained() -> String {
    String::from("unconstrained")
}

fn steering_locality_missing(context: &str) -> String {
    format!("missing:{context}")
}

fn steering_canary_pool_unpartitioned() -> String {
    String::from("unpartitioned")
}

fn steering_canary_pool_stable() -> String {
    String::from("stable")
}

fn steering_canary_pool_canary() -> String {
    String::from("canary")
}

fn steering_canary_pool_probe() -> String {
    String::from("canary_probe")
}

fn backend_matches_region(backend: &RouteBackend, region: &str) -> bool {
    backend
        .region
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case(region))
}

fn backend_matches_cell(backend: &RouteBackend, cell: &str) -> bool {
    backend
        .cell
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case(cell))
}

fn apply_locality_steering<'a>(
    candidates: Vec<&'a RouteBackend>,
    request: &EvaluateRouteRequest,
    policy: &SteeringPolicy,
) -> CandidateSelection<'a> {
    match policy.locality_mode {
        LocalityMode::None => CandidateSelection::Candidates {
            candidates,
            selected_locality: steering_locality_unconstrained(),
        },
        LocalityMode::Region => {
            let preferred_region =
                normalize_optional_locality_hint(request.preferred_region.as_deref());
            let Some(preferred_region) = preferred_region else {
                return if policy.fallback_to_any_healthy {
                    CandidateSelection::Candidates {
                        candidates,
                        selected_locality: steering_locality_fallback(),
                    }
                } else {
                    CandidateSelection::Denied {
                        reason: String::from(
                            "route steering policy requires preferred_region context",
                        ),
                        selected_locality: steering_locality_missing("preferred_region"),
                    }
                };
            };
            let regional = candidates
                .iter()
                .copied()
                .filter(|backend| backend_matches_region(backend, &preferred_region))
                .collect::<Vec<_>>();
            if !regional.is_empty() {
                CandidateSelection::Candidates {
                    candidates: regional,
                    selected_locality: steering_locality_region(&preferred_region),
                }
            } else if policy.fallback_to_any_healthy {
                CandidateSelection::Candidates {
                    candidates,
                    selected_locality: steering_locality_fallback(),
                }
            } else {
                CandidateSelection::Denied {
                    reason: String::from(
                        "route steering policy found no backend candidates for preferred locality",
                    ),
                    selected_locality: steering_locality_region(&preferred_region),
                }
            }
        }
        LocalityMode::Cell => {
            let preferred_cell =
                normalize_optional_locality_hint(request.preferred_cell.as_deref());
            let preferred_region =
                normalize_optional_locality_hint(request.preferred_region.as_deref());
            let has_locality_context = preferred_cell.is_some() || preferred_region.is_some();
            if let Some(preferred_cell) = preferred_cell.as_deref() {
                let cell_local = candidates
                    .iter()
                    .copied()
                    .filter(|backend| backend_matches_cell(backend, preferred_cell))
                    .collect::<Vec<_>>();
                if !cell_local.is_empty() {
                    return CandidateSelection::Candidates {
                        candidates: cell_local,
                        selected_locality: steering_locality_cell(preferred_cell),
                    };
                }
            }
            if let Some(preferred_region) = preferred_region.as_deref() {
                let regional = candidates
                    .iter()
                    .copied()
                    .filter(|backend| backend_matches_region(backend, preferred_region))
                    .collect::<Vec<_>>();
                if !regional.is_empty() {
                    return CandidateSelection::Candidates {
                        candidates: regional,
                        selected_locality: steering_locality_region(preferred_region),
                    };
                }
            }
            if policy.fallback_to_any_healthy {
                CandidateSelection::Candidates {
                    candidates,
                    selected_locality: steering_locality_fallback(),
                }
            } else if !has_locality_context {
                CandidateSelection::Denied {
                    reason: String::from(
                        "route steering policy requires preferred_cell or preferred_region context",
                    ),
                    selected_locality: steering_locality_missing("preferred_cell_or_region"),
                }
            } else {
                CandidateSelection::Denied {
                    reason: String::from(
                        "route steering policy found no backend candidates for preferred locality",
                    ),
                    selected_locality: preferred_cell
                        .as_deref()
                        .map(steering_locality_cell)
                        .or_else(|| preferred_region.as_deref().map(steering_locality_region))
                        .unwrap_or_else(steering_locality_unconstrained),
                }
            }
        }
    }
}

fn apply_canary_steering<'a>(
    candidates: Vec<&'a RouteBackend>,
    request: &EvaluateRouteRequest,
    policy: &SteeringPolicy,
    correlation_id: &str,
) -> (Vec<&'a RouteBackend>, String) {
    let canary = candidates
        .iter()
        .copied()
        .filter(|backend| backend.canary)
        .collect::<Vec<_>>();
    let stable = candidates
        .iter()
        .copied()
        .filter(|backend| !backend.canary)
        .collect::<Vec<_>>();
    if canary.is_empty() || stable.is_empty() {
        return (candidates, steering_canary_pool_unpartitioned());
    }

    let traffic_percent = policy.canary.traffic_percent.min(100);
    if traffic_percent == 0 {
        return (stable, steering_canary_pool_stable());
    }
    if traffic_percent == 100 {
        return (canary, steering_canary_pool_canary());
    }

    let steering_key = request
        .session_key
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            request
                .client_ip
                .as_deref()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or(correlation_id);
    let bucket = weighted_seed(steering_key) % 100;
    if bucket < u64::from(traffic_percent) {
        (canary, steering_canary_pool_canary())
    } else {
        (stable, steering_canary_pool_stable())
    }
}

async fn select_backend(
    route: &RouteRecord,
    request: &EvaluateRouteRequest,
    rr_cursor: &Arc<Mutex<HashMap<String, u64>>>,
    correlation_id: &str,
) -> Result<BackendSelectionOutcome> {
    // Backend selection happens in stages: start with healthy backends, enforce
    // half-open probe behavior, apply locality steering, apply canary
    // partitioning, and only then perform sticky-or-round-robin weighted
    // selection across the surviving candidates.
    let mut steering = SteeringAuditEvidence::default();
    let mut candidates = route
        .backends
        .iter()
        .filter(|backend| backend.healthy)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        steering.denial_reason = Some(String::from("route has no healthy backends"));
        return Ok(BackendSelectionOutcome::Denied(steering));
    }

    if route.policy_state.circuit_state == CircuitState::HalfOpen {
        let has_canary_pool = route.backends.iter().any(|backend| backend.canary);
        let canary = candidates
            .iter()
            .copied()
            .filter(|backend| backend.canary)
            .collect::<Vec<_>>();
        if has_canary_pool && canary.is_empty() {
            steering.selected_canary_pool = steering_canary_pool_probe();
            steering.denial_reason = Some(String::from(
                "route circuit breaker is half-open and no healthy canary probe backends are available",
            ));
            return Ok(BackendSelectionOutcome::Denied(steering));
        }
        if !canary.is_empty() {
            candidates = canary;
            steering.selected_canary_pool = steering_canary_pool_probe();
        } else {
            steering.selected_canary_pool = steering_canary_pool_unpartitioned();
        }
    }

    candidates = match apply_locality_steering(candidates, request, &route.steering_policy) {
        CandidateSelection::Candidates {
            candidates,
            selected_locality,
        } => {
            steering.selected_locality = selected_locality;
            candidates
        }
        CandidateSelection::Denied {
            reason,
            selected_locality,
        } => {
            steering.denial_reason = Some(reason);
            steering.selected_locality = selected_locality;
            return Ok(BackendSelectionOutcome::Denied(steering));
        }
    };

    if route.policy_state.circuit_state != CircuitState::HalfOpen {
        let (selected_candidates, selected_canary_pool) =
            apply_canary_steering(candidates, request, &route.steering_policy, correlation_id);
        candidates = selected_candidates;
        steering.selected_canary_pool = selected_canary_pool;
    }

    let total_weight = candidates
        .iter()
        .map(|backend| u64::from(backend.weight.max(1)))
        .sum::<u64>()
        .max(1);

    let seed = if route.sticky_session_policy.enabled {
        let sticky = request.session_key.as_deref().unwrap_or(correlation_id);
        weighted_seed(sticky)
    } else {
        let mut cursors = rr_cursor.lock().await;
        let cursor = cursors.entry(route.id.to_string()).or_insert(0);
        let current = *cursor;
        *cursor = cursor.saturating_add(1);
        current
    };
    let bucket = seed % total_weight;
    let mut running = 0_u64;
    for candidate in candidates {
        running = running.saturating_add(u64::from(candidate.weight.max(1)));
        if bucket < running {
            return Ok(BackendSelectionOutcome::Selected {
                backend: candidate.clone(),
                steering,
            });
        }
    }
    Err(PlatformError::unavailable(
        "weighted backend selection failed to choose a candidate",
    ))
}

fn weighted_seed(value: &str) -> u64 {
    let digest = sha256_hex(value.as_bytes());
    let prefix = digest.chars().take(16).collect::<String>();
    u64::from_str_radix(&prefix, 16).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use http_body_util::BodyExt;
    use serde::de::DeserializeOwned;
    use tempfile::tempdir;
    use time::OffsetDateTime;
    use uhost_api::ApiBody;
    use uhost_core::RequestContext;
    use uhost_types::{ChangeRequestId, PolicyId, PrivateNetworkId, ZoneId};

    use super::{
        CanarySteeringPolicy, CircuitBreakerPolicy, CircuitState, CreateRouteDnsBindingRequest,
        CreateRoutePrivateNetworkAttachmentRequest, CreateRoutePublicationRequest,
        CreateRoutePublicationTargetRequest, CreateRouteRequest,
        CreateRouteSecurityPolicyAttachmentRequest, EdgeExposureIntent, EvaluateRouteRequest,
        LocalityMode, RouteCircuitEventRequest, RouteHealthReportRequest, SteeringPolicy,
        StickySessionPolicy,
    };
    use crate::IngressService;

    async fn seed_inspection_profile_with_rules(
        service: &IngressService,
        inspection_profile_id: &PolicyId,
        blocked_countries: Vec<&str>,
        min_waf_score: u16,
        max_bot_score: u16,
        ddos_mode: &str,
    ) {
        service
            .inspection_profiles
            .create(
                inspection_profile_id.as_str(),
                super::InspectionProfileHook {
                    id: inspection_profile_id.to_string(),
                    name: String::from("edge-guard"),
                    blocked_countries: blocked_countries.into_iter().map(String::from).collect(),
                    min_waf_score,
                    max_bot_score,
                    ddos_mode: ddos_mode.to_owned(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn list_decision_audits(service: &IngressService) -> Vec<super::IngressDecisionAudit> {
        service
            .decision_audit
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect()
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

    async fn seed_dns_zone(service: &IngressService, zone_id: &ZoneId, domain: &str) {
        service
            .dns_zones
            .create(
                zone_id.as_str(),
                super::DnsZoneHook {
                    id: zone_id.to_string(),
                    domain: String::from(domain),
                    verified: false,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn seed_inspection_profile(service: &IngressService, inspection_profile_id: &PolicyId) {
        seed_inspection_profile_with_rules(
            service,
            inspection_profile_id,
            Vec::new(),
            0,
            1_000,
            "monitor",
        )
        .await;
    }

    async fn seed_private_network(service: &IngressService, private_network_id: &PrivateNetworkId) {
        service
            .private_networks
            .create(
                private_network_id.as_str(),
                super::PrivateNetworkHook {
                    id: private_network_id.clone(),
                    name: String::from("private-example"),
                    cidr: String::from("10.42.0.0/16"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn seed_ready_private_network_topology(
        service: &IngressService,
        private_network_id: &PrivateNetworkId,
    ) {
        let route_table_id = String::from("rtb_private_main");
        let next_hop_id = String::from("nhp_private_local");
        let private_route_id = String::from("prt_private_default");

        service
            .route_tables
            .create(
                &format!("{}:{route_table_id}", private_network_id.as_str()),
                super::PrivateTopologyRouteTableHook {
                    id: route_table_id.clone(),
                    private_network_id: private_network_id.clone(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .subnets
            .create(
                &format!("{}:snt_private_app", private_network_id.as_str()),
                super::PrivateTopologySubnetHook {
                    private_network_id: private_network_id.clone(),
                    route_table_id: Some(route_table_id.clone()),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .next_hops
            .create(
                &format!("{}:{next_hop_id}", private_network_id.as_str()),
                super::PrivateTopologyNextHopHook {
                    id: next_hop_id.clone(),
                    private_network_id: private_network_id.clone(),
                    kind: String::from("local"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .private_routes
            .create(
                &format!(
                    "{}:{route_table_id}:{private_route_id}",
                    private_network_id.as_str()
                ),
                super::PrivateTopologyRouteHook {
                    id: private_route_id,
                    private_network_id: private_network_id.clone(),
                    route_table_id,
                    next_hop_id,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn seed_governance_change_request(service: &IngressService, state: &str) -> String {
        let id = ChangeRequestId::generate().unwrap_or_else(|error| panic!("{error}"));
        service
            .governance_change_requests
            .create(
                id.as_str(),
                super::GovernanceChangeRequestMirror {
                    id: id.clone(),
                    state: state.to_owned(),
                    extra: std::collections::BTreeMap::new(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        id.to_string()
    }

    async fn seed_mail_domain(
        service: &IngressService,
        domain_id: &str,
        domain: &str,
        zone_id: Option<&ZoneId>,
        verified: bool,
    ) {
        service
            .mail_domains
            .create(
                domain_id,
                super::MailDomainHook {
                    id: String::from(domain_id),
                    domain: String::from(domain),
                    zone_id: zone_id.map(ToString::to_string),
                    verified,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn seed_mail_reputation(service: &IngressService, domain_id: &str, suspended: bool) {
        service
            .mail_reputation
            .create(
                domain_id,
                super::MailReputationHook {
                    domain_id: String::from(domain_id),
                    suspended,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn seed_mail_dead_letter(
        service: &IngressService,
        dead_letter_id: &str,
        domain_id: &str,
    ) {
        service
            .mail_dead_letters
            .create(
                dead_letter_id,
                super::MailDeadLetterHook {
                    domain_id: String::from(domain_id),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn seed_policy_record(
        service: &IngressService,
        policy_id: &str,
        effect: &str,
        selector: BTreeMap<String, String>,
    ) {
        service
            .policy_records
            .create(
                policy_id,
                super::PolicyRecordHook {
                    id: String::from(policy_id),
                    resource_kind: String::from("ingress_route"),
                    action: String::from("publish"),
                    effect: String::from(effect),
                    selector,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn seed_policy_approval(
        service: &IngressService,
        approval_id: &str,
        subject: &str,
        approved: bool,
    ) {
        service
            .policy_approvals
            .create(
                approval_id,
                super::PolicyApprovalHook {
                    subject: String::from(subject),
                    approved,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn seed_governance_legal_hold(service: &IngressService, hold_id: &str, active: bool) {
        service
            .governance_legal_holds
            .create(hold_id, super::GovernanceLegalHoldHook { active })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn seed_governance_checkpoint(
        service: &IngressService,
        checkpoint_id: &str,
        recorded_at: OffsetDateTime,
    ) {
        service
            .governance_audit_checkpoints
            .create(
                checkpoint_id,
                super::GovernanceAuditCheckpointHook { recorded_at },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn seed_abuse_quarantine(
        service: &IngressService,
        quarantine_id: &str,
        subject_kind: &str,
        subject: &str,
        deny_network: bool,
        deny_mail_relay: bool,
    ) {
        service
            .abuse_quarantines
            .create(
                quarantine_id,
                super::AbuseQuarantineHook {
                    subject_kind: String::from(subject_kind),
                    subject: String::from(subject),
                    state: String::from("active"),
                    deny_network,
                    deny_mail_relay,
                    expires_at: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[tokio::test]
    async fn create_route_defaults_public_exposure_and_preserves_evaluation() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let change_request_id = seed_governance_change_request(&service, "approved").await;

        let created = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("default-public.example.com"),
                    target: Some(String::from("http://127.0.0.1:8080")),
                    backends: Vec::new(),
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(change_request_id.clone()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_body = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let route: super::RouteRecord =
            serde_json::from_slice(&created_body).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(route.publication.exposure, EdgeExposureIntent::Public);
        assert!(route.publication.dns_binding.is_none());
        assert!(route.publication.security_policy.is_none());
        assert!(route.publication.private_network.is_none());
        let publication_evaluation = route
            .publication_evaluation
            .as_ref()
            .unwrap_or_else(|| panic!("missing publication evaluation snapshot"));
        assert!(publication_evaluation.admitted);
        assert_eq!(publication_evaluation.dns_binding, None);
        assert_eq!(publication_evaluation.security_policy, None);
        assert_eq!(publication_evaluation.private_network, None);
        assert_eq!(
            publication_evaluation.rationale,
            "public exposure admitted without auxiliary attachment snapshots"
        );
        assert_eq!(
            route
                .metadata
                .annotations
                .get("governance.change_request_id")
                .map(String::as_str),
            Some(change_request_id.as_str())
        );
        assert_eq!(
            route
                .metadata
                .annotations
                .get("ingress.mutation_digest")
                .map(String::len),
            Some(64)
        );
        let change_authorization = route
            .change_authorization
            .as_ref()
            .unwrap_or_else(|| panic!("missing route change authorization"));
        assert_eq!(
            change_authorization.change_request_id.as_str(),
            change_request_id.as_str()
        );
        assert_eq!(change_authorization.mutation_digest.len(), 64);

        let evaluated = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("default-public.example.com"),
                    protocol: Some(String::from("http")),
                    source_identity: None,
                    client_ip: Some(String::from("198.51.100.20")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(evaluated.admitted);
        let audits = list_decision_audits(&service).await;
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].verdict, "allow");
        assert!(audits[0].edge_policy.is_none());
    }

    #[tokio::test]
    async fn create_route_requires_approved_governance_change() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let missing = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("governed.example.com"),
                    target: Some(String::from("http://127.0.0.1:8080")),
                    backends: Vec::new(),
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: None,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected missing governance change rejection"));
        assert_eq!(missing.code, uhost_core::ErrorCode::Conflict);

        let pending_change_request_id = seed_governance_change_request(&service, "pending").await;
        let pending = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("pending-governed.example.com"),
                    target: Some(String::from("http://127.0.0.1:8080")),
                    backends: Vec::new(),
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(pending_change_request_id),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected pending governance change rejection"));
        assert_eq!(pending.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn create_route_honors_private_exposure_intent() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let private_network_id =
            PrivateNetworkId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_private_network(&service, &private_network_id).await;
        seed_ready_private_network_topology(&service, &private_network_id).await;

        let created = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("private-api.example.com"),
                    target: Some(String::from("http://127.0.0.1:18080")),
                    backends: Vec::new(),
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("private")),
                        dns_binding: None,
                        security_policy: None,
                        private_network: Some(CreateRoutePrivateNetworkAttachmentRequest {
                            private_network_id: private_network_id.to_string(),
                        }),
                        targets: Vec::new(),
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_body = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let route: super::RouteRecord =
            serde_json::from_slice(&created_body).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(route.publication.exposure, EdgeExposureIntent::Private);
        assert!(route.publication.dns_binding.is_none());
        assert!(route.publication.security_policy.is_none());
        assert_eq!(
            route
                .publication
                .private_network
                .as_ref()
                .map(|attachment| attachment.private_network_id.to_string()),
            Some(private_network_id.to_string())
        );
        let publication_evaluation = route
            .publication_evaluation
            .as_ref()
            .unwrap_or_else(|| panic!("missing publication evaluation snapshot"));
        assert!(publication_evaluation.admitted);
        let private_network_snapshot = publication_evaluation
            .private_network
            .as_ref()
            .unwrap_or_else(|| panic!("missing private network snapshot"));
        assert_eq!(
            private_network_snapshot.private_network_id.to_string(),
            private_network_id.to_string()
        );
        assert_eq!(
            private_network_snapshot.private_network_name,
            "private-example"
        );
        assert_eq!(private_network_snapshot.cidr, "10.42.0.0/16");
        assert!(private_network_snapshot.topology.ready);
        assert_eq!(private_network_snapshot.topology.subnet_count, 1);
        assert_eq!(
            private_network_snapshot
                .topology
                .subnets_with_route_table_count,
            1
        );
        assert_eq!(private_network_snapshot.topology.route_table_count, 1);
        assert_eq!(private_network_snapshot.topology.private_route_count, 1);
        assert_eq!(
            private_network_snapshot.topology.ready_private_route_count,
            1
        );
        assert_eq!(
            private_network_snapshot.rationale,
            "private exposure anchored to private network private-example (10.42.0.0/16); topology is ready via 1 routed subnets, 1 ready private routes, 0 service-connect attachments, and 0 transit/vpn/peering attachments"
        );
        assert_eq!(publication_evaluation.dns_binding, None);
        assert_eq!(publication_evaluation.security_policy, None);

        let evaluated = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("private-api.example.com"),
                    protocol: Some(String::from("http")),
                    source_identity: None,
                    client_ip: Some(String::from("203.0.113.5")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: Some(private_network_id.to_string()),
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(evaluated.admitted);
    }

    #[tokio::test]
    async fn create_route_rejects_private_exposure_without_private_network_attachment() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("private-no-attachment.example.com"),
                    target: Some(String::from("http://127.0.0.1:18083")),
                    backends: Vec::new(),
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("private")),
                        dns_binding: None,
                        security_policy: None,
                        private_network: None,
                        targets: Vec::new(),
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .expect_err("private exposure without private network should be rejected");

        assert!(
            error
                .to_string()
                .contains("private exposure routes must attach private_network")
        );
    }

    #[tokio::test]
    async fn create_route_rejects_private_exposure_without_ready_topology() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let private_network_id =
            PrivateNetworkId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_private_network(&service, &private_network_id).await;

        let error = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("private-unready.example.com"),
                    target: Some(String::from("http://127.0.0.1:18084")),
                    backends: Vec::new(),
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("private")),
                        dns_binding: None,
                        security_policy: None,
                        private_network: Some(CreateRoutePrivateNetworkAttachmentRequest {
                            private_network_id: private_network_id.to_string(),
                        }),
                        targets: Vec::new(),
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .expect_err("private exposure without routed topology should be rejected");

        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert!(
            error
                .message
                .contains("private_network topology is not ready for private exposure")
        );
        assert!(
            error
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("no subnets exist"))
        );
    }

    #[tokio::test]
    async fn private_route_rejects_when_private_topology_becomes_unready() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let private_network_id =
            PrivateNetworkId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_private_network(&service, &private_network_id).await;
        seed_ready_private_network_topology(&service, &private_network_id).await;

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("private-runtime-topology.example.com"),
                    target: Some(String::from("http://127.0.0.1:18085")),
                    backends: Vec::new(),
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("private")),
                        dns_binding: None,
                        security_policy: None,
                        private_network: Some(CreateRoutePrivateNetworkAttachmentRequest {
                            private_network_id: private_network_id.to_string(),
                        }),
                        targets: Vec::new(),
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let private_route_key = format!(
            "{}:rtb_private_main:prt_private_default",
            private_network_id.as_str()
        );
        let stored_private_route = service
            .private_routes
            .get(&private_route_key)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("expected seeded private route"));
        service
            .private_routes
            .soft_delete(&private_route_key, Some(stored_private_route.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let evaluated = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("private-runtime-topology.example.com"),
                    protocol: Some(String::from("http")),
                    source_identity: None,
                    client_ip: Some(String::from("203.0.113.17")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: Some(private_network_id.to_string()),
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(!evaluated.admitted);
        assert_eq!(
            evaluated.reason,
            "private route attached private network topology is not ready: no reachable private routes or transit/vpn/peering attachments exist"
        );
    }

    #[tokio::test]
    async fn private_route_rejects_missing_private_network_context() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let private_network_id =
            PrivateNetworkId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_private_network(&service, &private_network_id).await;
        seed_ready_private_network_topology(&service, &private_network_id).await;

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("private-missing.example.com"),
                    target: Some(String::from("http://127.0.0.1:18081")),
                    backends: Vec::new(),
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("private")),
                        dns_binding: None,
                        security_policy: None,
                        private_network: Some(CreateRoutePrivateNetworkAttachmentRequest {
                            private_network_id: private_network_id.to_string(),
                        }),
                        targets: Vec::new(),
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let evaluated = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("private-missing.example.com"),
                    protocol: Some(String::from("http")),
                    source_identity: None,
                    client_ip: Some(String::from("203.0.113.15")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(!evaluated.admitted);
        assert_eq!(
            evaluated.reason,
            "private route requires private_network_id context"
        );
    }

    #[tokio::test]
    async fn private_route_rejects_mismatched_private_network_context() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let route_private_network_id =
            PrivateNetworkId::generate().unwrap_or_else(|error| panic!("{error}"));
        let request_private_network_id =
            PrivateNetworkId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_private_network(&service, &route_private_network_id).await;
        seed_private_network(&service, &request_private_network_id).await;
        seed_ready_private_network_topology(&service, &route_private_network_id).await;
        seed_ready_private_network_topology(&service, &request_private_network_id).await;

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("private-mismatch.example.com"),
                    target: Some(String::from("http://127.0.0.1:18082")),
                    backends: Vec::new(),
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("private")),
                        dns_binding: None,
                        security_policy: None,
                        private_network: Some(CreateRoutePrivateNetworkAttachmentRequest {
                            private_network_id: route_private_network_id.to_string(),
                        }),
                        targets: Vec::new(),
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let evaluated = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("private-mismatch.example.com"),
                    protocol: Some(String::from("http")),
                    source_identity: None,
                    client_ip: Some(String::from("203.0.113.16")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: Some(request_private_network_id.to_string()),
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(!evaluated.admitted);
        assert_eq!(
            evaluated.reason,
            "private_network_id does not match route private network"
        );
    }

    #[tokio::test]
    async fn create_route_accepts_valid_public_dns_and_security_attachments() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let zone_id = ZoneId::generate().unwrap_or_else(|error| panic!("{error}"));
        let inspection_profile_id = PolicyId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_dns_zone(&service, &zone_id, "example.com").await;
        seed_inspection_profile(&service, &inspection_profile_id).await;

        let created = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("api.example.com"),
                    target: Some(String::from("http://127.0.0.1:8081")),
                    backends: Vec::new(),
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("public")),
                        dns_binding: Some(CreateRouteDnsBindingRequest {
                            zone_id: zone_id.to_string(),
                        }),
                        security_policy: Some(CreateRouteSecurityPolicyAttachmentRequest {
                            inspection_profile_id: inspection_profile_id.to_string(),
                        }),
                        private_network: None,
                        targets: Vec::new(),
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_body = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let route: super::RouteRecord =
            serde_json::from_slice(&created_body).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(route.publication.exposure, EdgeExposureIntent::Public);
        assert_eq!(
            route
                .publication
                .dns_binding
                .as_ref()
                .map(|binding| binding.zone_id.to_string()),
            Some(zone_id.to_string())
        );
        assert_eq!(
            route
                .publication
                .security_policy
                .as_ref()
                .map(|policy| policy.inspection_profile_id.to_string()),
            Some(inspection_profile_id.to_string())
        );
        assert!(route.publication.private_network.is_none());
        let publication_evaluation = route
            .publication_evaluation
            .as_ref()
            .unwrap_or_else(|| panic!("missing publication evaluation snapshot"));
        assert!(publication_evaluation.admitted);
        let dns_binding_snapshot = publication_evaluation
            .dns_binding
            .as_ref()
            .unwrap_or_else(|| panic!("missing dns binding snapshot"));
        assert_eq!(
            dns_binding_snapshot.zone_id.to_string(),
            zone_id.to_string()
        );
        assert_eq!(dns_binding_snapshot.domain, "example.com");
        assert!(!dns_binding_snapshot.verified);
        assert_eq!(
            dns_binding_snapshot.rationale,
            "hostname api.example.com is covered by managed zone example.com but verification is still pending"
        );
        let security_policy_snapshot = publication_evaluation
            .security_policy
            .as_ref()
            .unwrap_or_else(|| panic!("missing security policy snapshot"));
        assert_eq!(
            security_policy_snapshot.inspection_profile_id.to_string(),
            inspection_profile_id.to_string()
        );
        assert_eq!(
            security_policy_snapshot.inspection_profile_name,
            "edge-guard"
        );
        assert_eq!(
            security_policy_snapshot.blocked_countries,
            Vec::<String>::new()
        );
        assert_eq!(security_policy_snapshot.min_waf_score, 0);
        assert_eq!(security_policy_snapshot.max_bot_score, 1_000);
        assert_eq!(security_policy_snapshot.ddos_mode, "monitor");
        assert_eq!(
            security_policy_snapshot.rationale,
            "protocol https captured inspection profile edge-guard for durable exposure evaluation"
        );
        assert_eq!(publication_evaluation.private_network, None);
    }

    #[test]
    fn route_record_deserialization_defaults_missing_publication_evaluation() {
        let route_id = uhost_types::RouteId::generate().unwrap_or_else(|error| panic!("{error}"));
        let legacy_timestamp = serde_json::to_value(
            OffsetDateTime::from_unix_timestamp(1_767_225_600)
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let legacy_record = serde_json::json!({
            "id": route_id,
            "hostname": "legacy.example.com",
            "target": "http://127.0.0.1:8080",
            "protocol": "http",
            "tls_mode": "offload",
            "metadata": {
                "created_at": legacy_timestamp.clone(),
                "updated_at": legacy_timestamp.clone(),
                "lifecycle": "pending",
                "ownership_scope": "project",
                "owner_id": "route-owner",
                "labels": {},
                "annotations": {},
                "deleted_at": null,
                "etag": "legacy-etag"
            },
            "publication": {
                "exposure": "public",
                "targets": []
            },
            "backends": [{
                "id": "backend-1",
                "target": "http://127.0.0.1:8080",
                "weight": 1,
                "healthy": true,
                "failure_count": 0,
                "last_checked_at": null
            }],
            "health_check": {
                "path": "/healthz",
                "interval_seconds": 10,
                "timeout_ms": 2000,
                "unhealthy_threshold": 3,
                "healthy_threshold": 2
            },
            "retry_policy": {
                "max_attempts": 3,
                "initial_backoff_ms": 50,
                "max_backoff_ms": 400,
                "retry_on_5xx": true,
                "retry_on_connect_failure": true
            },
            "circuit_breaker": {
                "failure_threshold": 5,
                "success_threshold": 2,
                "open_interval_seconds": 30
            },
            "timeout_policy": {
                "connect_timeout_ms": 2000,
                "request_timeout_ms": 30000,
                "idle_timeout_ms": 60000
            },
            "header_policy": {
                "normalize_host": true,
                "strip_hop_by_hop": true,
                "set_forwarded_headers": true
            },
            "compression_policy": {
                "enabled": true,
                "min_size_bytes": 1024
            },
            "rate_limit_policy": {
                "requests_per_minute": 600,
                "burst": 120
            },
            "sticky_session_policy": {
                "enabled": false,
                "cookie_name": "uhost_route",
                "ttl_seconds": 86400
            },
            "service_identity_policy": {
                "required": false,
                "require_mtls": false,
                "allowed_subject_prefixes": []
            },
            "steering_policy": {
                "locality_mode": "none",
                "fallback_to_any_healthy": true,
                "canary": {
                    "enabled": false,
                    "traffic_percent": 0
                }
            },
            "policy_state": {
                "circuit_state": "closed",
                "opened_at": null,
                "consecutive_failures": 0,
                "consecutive_successes": 0,
                "last_transition_at": legacy_timestamp
            }
        });
        let route: super::RouteRecord =
            serde_json::from_value(legacy_record).unwrap_or_else(|error| panic!("{error}"));
        assert!(route.publication_evaluation.is_none());
    }

    #[tokio::test]
    async fn create_route_persists_explicit_publication_targets() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("targets.example.com"),
                    target: Some(String::from("https://127.0.0.1:9443")),
                    backends: Vec::new(),
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("public")),
                        dns_binding: None,
                        security_policy: None,
                        private_network: None,
                        targets: vec![
                            CreateRoutePublicationTargetRequest {
                                cell: String::from("use1-edge-a"),
                                region: String::from("us-east-1"),
                                failover_group: Some(String::from("public-api")),
                                drain: false,
                                tls_owner: String::from("platform-edge"),
                            },
                            CreateRoutePublicationTargetRequest {
                                cell: String::from("use1-edge-b"),
                                region: String::from("us-east-1"),
                                failover_group: Some(String::from("public-api")),
                                drain: true,
                                tls_owner: String::from("platform-edge"),
                            },
                        ],
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_body = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let route: super::RouteRecord =
            serde_json::from_slice(&created_body).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(route.publication.targets.len(), 2);
        assert_eq!(route.publication.targets[0].cell, "use1-edge-a");
        assert_eq!(route.publication.targets[0].region, "us-east-1");
        assert_eq!(
            route.publication.targets[0].failover_group.as_deref(),
            Some("public-api")
        );
        assert!(!route.publication.targets[0].drain);
        assert_eq!(route.publication.targets[0].tls_owner, "platform-edge");
        assert_ne!(
            route.publication.targets[0].id.to_string(),
            route.publication.targets[1].id.to_string()
        );
    }

    #[tokio::test]
    async fn create_route_rejects_duplicate_publication_targets() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("duplicate-targets.example.com"),
                    target: Some(String::from("https://127.0.0.1:9443")),
                    backends: Vec::new(),
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("public")),
                        dns_binding: None,
                        security_policy: None,
                        private_network: None,
                        targets: vec![
                            CreateRoutePublicationTargetRequest {
                                cell: String::from("use1-edge-a"),
                                region: String::from("us-east-1"),
                                failover_group: Some(String::from("public-api")),
                                drain: false,
                                tls_owner: String::from("platform-edge"),
                            },
                            CreateRoutePublicationTargetRequest {
                                cell: String::from("use1-edge-a"),
                                region: String::from("us-east-1"),
                                failover_group: Some(String::from("public-api")),
                                drain: true,
                                tls_owner: String::from("platform-edge"),
                            },
                        ],
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .expect_err("duplicate publication target placement should be rejected");

        assert!(
            error.to_string().contains(
                "publication targets must be unique per cell, region, and failover_group"
            )
        );
    }

    #[tokio::test]
    async fn evaluate_route_rejects_when_all_publication_targets_are_draining() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("drained-targets.example.com"),
                    target: Some(String::from("https://127.0.0.1:9443")),
                    backends: Vec::new(),
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("public")),
                        dns_binding: None,
                        security_policy: None,
                        private_network: None,
                        targets: vec![CreateRoutePublicationTargetRequest {
                            cell: String::from("use1-edge-a"),
                            region: String::from("us-east-1"),
                            failover_group: Some(String::from("public-api")),
                            drain: true,
                            tls_owner: String::from("platform-edge"),
                        }],
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let evaluated = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("drained-targets.example.com"),
                    protocol: Some(String::from("https")),
                    source_identity: None,
                    client_ip: Some(String::from("198.51.100.60")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(!evaluated.admitted);
        assert_eq!(evaluated.reason, "route has no active publication targets");
    }

    #[tokio::test]
    async fn ingress_summary_reflects_persisted_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let zone_ready = ZoneId::generate().unwrap_or_else(|error| panic!("{error}"));
        let zone_pending = ZoneId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_dns_zone(&service, &zone_ready, "example.com").await;
        seed_dns_zone(&service, &zone_pending, "pending.example").await;
        let stored_zone = service
            .dns_zones
            .get(zone_ready.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("expected ready zone"));
        let mut ready_zone = stored_zone.value;
        ready_zone.verified = true;
        service
            .dns_zones
            .upsert(zone_ready.as_str(), ready_zone, Some(stored_zone.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let inspection_profile_id = PolicyId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_inspection_profile(&service, &inspection_profile_id).await;
        let private_network_id =
            PrivateNetworkId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_private_network(&service, &private_network_id).await;
        seed_ready_private_network_topology(&service, &private_network_id).await;

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("public.example.com"),
                    target: Some(String::from("http://127.0.0.1:8080")),
                    backends: Vec::new(),
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("public")),
                        dns_binding: Some(CreateRouteDnsBindingRequest {
                            zone_id: zone_ready.to_string(),
                        }),
                        security_policy: Some(CreateRouteSecurityPolicyAttachmentRequest {
                            inspection_profile_id: inspection_profile_id.to_string(),
                        }),
                        private_network: None,
                        targets: vec![
                            CreateRoutePublicationTargetRequest {
                                cell: String::from("use1-edge-a"),
                                region: String::from("us-east-1"),
                                failover_group: Some(String::from("public-api")),
                                drain: false,
                                tls_owner: String::from("platform-edge"),
                            },
                            CreateRoutePublicationTargetRequest {
                                cell: String::from("use1-edge-b"),
                                region: String::from("us-east-1"),
                                failover_group: Some(String::from("public-api")),
                                drain: false,
                                tls_owner: String::from("platform-edge"),
                            },
                        ],
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("private.example.com"),
                    target: Some(String::from("http://127.0.0.1:9000")),
                    backends: Vec::new(),
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("passthrough"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("private")),
                        dns_binding: None,
                        security_policy: None,
                        private_network: Some(CreateRoutePrivateNetworkAttachmentRequest {
                            private_network_id: private_network_id.to_string(),
                        }),
                        targets: vec![CreateRoutePublicationTargetRequest {
                            cell: String::from("usw2-private-a"),
                            region: String::from("us-west-2"),
                            failover_group: Some(String::from("private-api")),
                            drain: true,
                            tls_owner: String::from("tenant-edge"),
                        }],
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .ingress_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.total_routes, 2);
        assert_eq!(summary.total_sites, 2);
        assert_eq!(summary.total_backends, 2);
        assert_eq!(summary.total_dns_bindings, 1);
        assert_eq!(summary.total_dns_zones, 2);
        assert_eq!(summary.dns_ready_domains, 1);
        assert_eq!(summary.dns_pending_domains, 1);
        assert_eq!(summary.total_edge_policy_routes, 1);
        assert_eq!(summary.total_inspection_profiles, 1);
        assert_eq!(summary.total_private_routes, 1);
        assert_eq!(summary.total_private_networks, 1);
        assert_eq!(summary.total_publication_targets, 3);
        assert_eq!(summary.draining_publication_targets, 1);
        assert_eq!(summary.publication_regions, 2);
        assert_eq!(summary.publication_cells, 3);
        assert_eq!(summary.publication_failover_groups, 2);
    }

    #[tokio::test]
    async fn exposure_evidence_joins_ingress_dns_netsec_mail_policy_and_governance() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let zone_id = ZoneId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_dns_zone(&service, &zone_id, "example.com").await;

        let inspection_profile_id = PolicyId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_inspection_profile(&service, &inspection_profile_id).await;

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("api.example.com"),
                    target: Some(String::from("https://127.0.0.1:9443")),
                    backends: Vec::new(),
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("public")),
                        dns_binding: Some(CreateRouteDnsBindingRequest {
                            zone_id: zone_id.to_string(),
                        }),
                        security_policy: Some(CreateRouteSecurityPolicyAttachmentRequest {
                            inspection_profile_id: inspection_profile_id.to_string(),
                        }),
                        private_network: None,
                        targets: vec![CreateRoutePublicationTargetRequest {
                            cell: String::from("use1-edge-a"),
                            region: String::from("us-east-1"),
                            failover_group: Some(String::from("public-api")),
                            drain: false,
                            tls_owner: String::from("platform-edge"),
                        }],
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        seed_mail_domain(
            &service,
            "mail-domain-1",
            "example.com",
            Some(&zone_id),
            false,
        )
        .await;
        seed_mail_reputation(&service, "mail-domain-1", true).await;
        seed_mail_dead_letter(&service, "dead-letter-1", "mail-domain-1").await;
        seed_policy_record(
            &service,
            "policy-route-deny",
            "deny",
            BTreeMap::from([(String::from("hostname"), String::from("api.example.com"))]),
        )
        .await;
        seed_policy_record(
            &service,
            "policy-zone-allow",
            "allow",
            BTreeMap::from([(String::from("zone_id"), zone_id.to_string())]),
        )
        .await;
        seed_policy_approval(&service, "approval-1", "api.example.com", false).await;
        seed_governance_change_request(&service, "pending").await;
        seed_governance_legal_hold(&service, "hold-1", true).await;
        seed_governance_checkpoint(&service, "checkpoint-1", OffsetDateTime::now_utc()).await;
        seed_abuse_quarantine(
            &service,
            "quarantine-host",
            "hostname",
            "api.example.com",
            true,
            false,
        )
        .await;
        seed_abuse_quarantine(
            &service,
            "quarantine-mail",
            "mail_domain",
            "example.com",
            false,
            true,
        )
        .await;

        let report = service
            .exposure_evidence()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(report.summary.total_routes, 1);
        assert_eq!(report.summary.public_routes, 1);
        assert_eq!(report.summary.private_routes, 0);
        assert_eq!(report.summary.routes_requiring_attention, 1);
        assert_eq!(report.summary.routes_with_verified_dns, 0);
        assert_eq!(report.summary.routes_without_active_targets, 0);
        assert_eq!(report.summary.routes_with_mail_risk, 1);
        assert_eq!(report.summary.routes_with_policy_matches, 1);

        let route = report
            .routes
            .first()
            .unwrap_or_else(|| panic!("expected one route in report"));
        assert_eq!(route.hostname, "api.example.com");
        assert_eq!(route.exposure, "public");
        assert_eq!(route.active_publication_targets, 1);
        assert_eq!(route.healthy_backends, 1);
        assert!(route.dns.binding_present);
        assert_eq!(route.dns.zone_id.as_deref(), Some(zone_id.as_str()));
        assert_eq!(route.dns.zone_domain.as_deref(), Some("example.com"));
        assert_eq!(route.dns.zone_verified, Some(false));
        assert!(route.netsec.inspection_profile_present);
        assert_eq!(
            route.netsec.inspection_profile_id.as_deref(),
            Some(inspection_profile_id.as_str())
        );
        assert_eq!(
            route.netsec.inspection_profile_name.as_deref(),
            Some("edge-guard")
        );
        assert!(route.netsec.hostname_quarantine_active);
        assert_eq!(
            route.mail.related_domains,
            vec![String::from("example.com")]
        );
        assert_eq!(route.mail.verified_domains, 0);
        assert_eq!(route.mail.suspended_domains, 1);
        assert_eq!(route.mail.active_relay_quarantines, 1);
        assert_eq!(route.mail.dead_letter_count, 1);
        assert_eq!(route.policy.matched_policies, 2);
        assert_eq!(route.policy.matched_allow_policies, 1);
        assert_eq!(route.policy.matched_deny_policies, 1);
        assert_eq!(
            route.policy.matched_policy_ids,
            vec![
                String::from("policy-route-deny"),
                String::from("policy-zone-allow")
            ]
        );
        assert!(
            route
                .attention_reasons
                .iter()
                .any(|value| value == "bound dns zone is not verified")
        );
        assert!(
            route
                .attention_reasons
                .iter()
                .any(|value| value == "hostname has an active network quarantine")
        );
        assert!(
            route
                .attention_reasons
                .iter()
                .any(|value| value == "related mail domain relay is suspended")
        );
        assert!(
            route
                .attention_reasons
                .iter()
                .any(|value| value == "related mail domain has an active relay quarantine")
        );

        assert_eq!(report.policy.total_policies, 2);
        assert_eq!(report.policy.allow_policies, 1);
        assert_eq!(report.policy.deny_policies, 1);
        assert_eq!(report.policy.matched_route_policies, 2);
        assert_eq!(report.policy.total_approvals, 1);
        assert_eq!(report.policy.pending_approvals, 1);

        assert_eq!(report.governance.total_change_requests, 2);
        assert_eq!(report.governance.pending_change_requests, 1);
        assert_eq!(report.governance.approved_change_requests, 1);
        assert_eq!(report.governance.applied_change_requests, 0);
        assert_eq!(report.governance.active_legal_holds, 1);
        assert_eq!(report.governance.audit_checkpoints, 1);
        assert!(report.governance.latest_checkpoint_at.is_some());
    }

    #[tokio::test]
    async fn create_route_rejects_mismatched_zone_binding() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let zone_id = ZoneId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_dns_zone(&service, &zone_id, "other.example").await;

        let error = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("api.example.com"),
                    target: Some(String::from("http://127.0.0.1:8082")),
                    backends: Vec::new(),
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("public")),
                        dns_binding: Some(CreateRouteDnsBindingRequest {
                            zone_id: zone_id.to_string(),
                        }),
                        security_policy: None,
                        private_network: None,
                        targets: Vec::new(),
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .expect_err("mismatched zone binding should be rejected");
        assert!(
            error
                .to_string()
                .contains("zone_id is not authorized for this ingress hostname")
        );
    }

    #[tokio::test]
    async fn create_route_rejects_security_policy_attachment_for_tcp_routes() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let inspection_profile_id = PolicyId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_inspection_profile(&service, &inspection_profile_id).await;

        let error = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("tcp.example.com"),
                    target: Some(String::from("tcp://127.0.0.1:9000")),
                    backends: Vec::new(),
                    protocol: String::from("tcp"),
                    sticky_sessions: false,
                    tls_mode: String::from("passthrough"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("public")),
                        dns_binding: None,
                        security_policy: Some(CreateRouteSecurityPolicyAttachmentRequest {
                            inspection_profile_id: inspection_profile_id.to_string(),
                        }),
                        private_network: None,
                        targets: Vec::new(),
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .expect_err("tcp edge security attachment should be rejected");
        assert!(
            error
                .to_string()
                .contains("security_policy requires protocol http, https, websocket, or grpc")
        );
    }

    #[tokio::test]
    async fn create_route_rejects_unknown_security_policy_attachment() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let inspection_profile_id = PolicyId::generate().unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("unknown-policy.example.com"),
                    target: Some(String::from("https://127.0.0.1:9443")),
                    backends: Vec::new(),
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("public")),
                        dns_binding: None,
                        security_policy: Some(CreateRouteSecurityPolicyAttachmentRequest {
                            inspection_profile_id: inspection_profile_id.to_string(),
                        }),
                        private_network: None,
                        targets: Vec::new(),
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .expect_err("unknown edge security attachment should be rejected");
        assert!(
            error
                .to_string()
                .contains("inspection profile does not exist")
        );
    }

    #[tokio::test]
    async fn evaluate_route_enforces_attached_security_policy_and_records_deny_evidence() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let inspection_profile_id = PolicyId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_inspection_profile_with_rules(
            &service,
            &inspection_profile_id,
            vec!["CN"],
            0,
            1_000,
            "monitor",
        )
        .await;

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("secured.example.com"),
                    target: Some(String::from("https://127.0.0.1:8443")),
                    backends: Vec::new(),
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("public")),
                        dns_binding: None,
                        security_policy: Some(CreateRouteSecurityPolicyAttachmentRequest {
                            inspection_profile_id: inspection_profile_id.to_string(),
                        }),
                        private_network: None,
                        targets: Vec::new(),
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let denied = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("secured.example.com"),
                    protocol: Some(String::from("https")),
                    source_identity: None,
                    client_ip: Some(String::from("198.51.100.31")),
                    session_key: None,
                    request_path: Some(String::from("/login")),
                    source_country: Some(String::from("CN")),
                    waf_score: Some(900),
                    bot_score: Some(20),
                    ddos_suspected: Some(false),
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!denied.admitted);
        assert_eq!(denied.reason, "blocked by geo restriction for country CN");

        let audits = list_decision_audits(&service).await;
        assert_eq!(audits.len(), 1);
        let audit = &audits[0];
        assert_eq!(audit.verdict, "deny");
        assert_eq!(audit.reason, "blocked by geo restriction for country CN");
        let edge_policy = audit
            .edge_policy
            .as_ref()
            .unwrap_or_else(|| panic!("missing edge policy evidence"));
        assert_eq!(
            edge_policy.inspection_profile_id,
            inspection_profile_id.to_string()
        );
        assert_eq!(edge_policy.inspection_profile_name, "edge-guard");
        assert_eq!(edge_policy.request_path, "/login");
        assert_eq!(edge_policy.verdict, "deny");
        assert_eq!(
            edge_policy.reason,
            "blocked by geo restriction for country CN"
        );
        assert_eq!(edge_policy.source_country.as_deref(), Some("CN"));
        assert_eq!(edge_policy.waf_score, Some(900));
        assert_eq!(edge_policy.bot_score, Some(20));
        assert!(!edge_policy.ddos_suspected);
    }

    #[tokio::test]
    async fn evaluate_route_records_allow_evidence_for_attached_security_policy() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let inspection_profile_id = PolicyId::generate().unwrap_or_else(|error| panic!("{error}"));
        seed_inspection_profile_with_rules(
            &service,
            &inspection_profile_id,
            vec!["CN"],
            400,
            250,
            "monitor",
        )
        .await;

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("edge-allow.example.com"),
                    target: Some(String::from("https://127.0.0.1:9443")),
                    backends: Vec::new(),
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: Some(CreateRoutePublicationRequest {
                        exposure: Some(String::from("public")),
                        dns_binding: None,
                        security_policy: Some(CreateRouteSecurityPolicyAttachmentRequest {
                            inspection_profile_id: inspection_profile_id.to_string(),
                        }),
                        private_network: None,
                        targets: Vec::new(),
                    }),
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let allowed = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("edge-allow.example.com"),
                    protocol: Some(String::from("https")),
                    source_identity: None,
                    client_ip: Some(String::from("198.51.100.32")),
                    session_key: None,
                    request_path: Some(String::from("/checkout")),
                    source_country: Some(String::from("US")),
                    waf_score: Some(500),
                    bot_score: Some(20),
                    ddos_suspected: Some(false),
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(allowed.admitted);

        let audits = list_decision_audits(&service).await;
        assert_eq!(audits.len(), 1);
        let audit = &audits[0];
        assert_eq!(audit.verdict, "allow");
        let edge_policy = audit
            .edge_policy
            .as_ref()
            .unwrap_or_else(|| panic!("missing edge policy evidence"));
        assert_eq!(
            edge_policy.inspection_profile_id,
            inspection_profile_id.to_string()
        );
        assert_eq!(edge_policy.request_path, "/checkout");
        assert_eq!(edge_policy.verdict, "allow");
        assert_eq!(edge_policy.reason, "inspection profile passed");
        assert_eq!(edge_policy.source_country.as_deref(), Some("US"));
    }

    #[tokio::test]
    async fn evaluate_route_selects_weighted_backend() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("api.example.com"),
                    target: None,
                    backends: vec![
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.10:8080"),
                            weight: Some(1),
                            region: None,
                            cell: None,
                            canary: false,
                        },
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.11:8080"),
                            weight: Some(2),
                            region: None,
                            cell: None,
                            canary: false,
                        },
                    ],
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let result = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("api.example.com"),
                    protocol: Some(String::from("https")),
                    source_identity: None,
                    client_ip: Some(String::from("203.0.113.9")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(result.admitted);
        assert!(result.selected_backend.is_some());
    }

    #[tokio::test]
    async fn evaluate_route_prefers_cell_local_backend_when_steering_policy_matches() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("locality.example.com"),
                    target: None,
                    backends: vec![
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.41:8080"),
                            weight: Some(1),
                            region: Some(String::from("us-east-1")),
                            cell: Some(String::from("use1-edge-a")),
                            canary: false,
                        },
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.42:8080"),
                            weight: Some(1),
                            region: Some(String::from("us-west-2")),
                            cell: Some(String::from("usw2-edge-a")),
                            canary: false,
                        },
                    ],
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: Some(SteeringPolicy {
                        locality_mode: LocalityMode::Cell,
                        fallback_to_any_healthy: true,
                        canary: CanarySteeringPolicy::default(),
                    }),
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let evaluated = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("locality.example.com"),
                    protocol: Some(String::from("https")),
                    source_identity: None,
                    client_ip: Some(String::from("198.51.100.70")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: Some(String::from("us-east-1")),
                    preferred_cell: Some(String::from("use1-edge-a")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(evaluated.admitted);
        assert_eq!(evaluated.selected_backend_id.as_deref(), Some("backend-1"));

        let audits = list_decision_audits(&service).await;
        assert_eq!(audits.len(), 1);
        let audit = &audits[0];
        assert_eq!(audit.selected_locality, "cell:use1-edge-a");
        assert_eq!(audit.selected_canary_pool, "unpartitioned");
        assert!(audit.steering_denial_reason.is_none());
    }

    #[tokio::test]
    async fn evaluate_route_uses_region_fallback_when_cell_mode_lacks_cell_context() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("regional-fallback.example.com"),
                    target: None,
                    backends: vec![
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.43:8080"),
                            weight: Some(1),
                            region: Some(String::from("us-east-1")),
                            cell: None,
                            canary: false,
                        },
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.44:8080"),
                            weight: Some(1),
                            region: Some(String::from("us-west-2")),
                            cell: Some(String::from("usw2-edge-a")),
                            canary: false,
                        },
                    ],
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: Some(SteeringPolicy {
                        locality_mode: LocalityMode::Cell,
                        fallback_to_any_healthy: false,
                        canary: CanarySteeringPolicy::default(),
                    }),
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let evaluated = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("regional-fallback.example.com"),
                    protocol: Some(String::from("https")),
                    source_identity: None,
                    client_ip: Some(String::from("198.51.100.75")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: Some(String::from("us-east-1")),
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(evaluated.admitted);
        assert_eq!(evaluated.selected_backend_id.as_deref(), Some("backend-1"));
    }

    #[tokio::test]
    async fn evaluate_route_falls_back_when_local_backend_is_unhealthy() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("locality-health.example.com"),
                    target: None,
                    backends: vec![
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.51:8080"),
                            weight: Some(1),
                            region: Some(String::from("us-east-1")),
                            cell: Some(String::from("use1-edge-a")),
                            canary: false,
                        },
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.52:8080"),
                            weight: Some(1),
                            region: Some(String::from("us-west-2")),
                            cell: Some(String::from("usw2-edge-a")),
                            canary: false,
                        },
                    ],
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: Some(SteeringPolicy {
                        locality_mode: LocalityMode::Cell,
                        fallback_to_any_healthy: true,
                        canary: CanarySteeringPolicy::default(),
                    }),
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_body = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let route: super::RouteRecord =
            serde_json::from_slice(&created_body).unwrap_or_else(|error| panic!("{error}"));

        service
            .report_backend_health(
                route.id.as_str(),
                RouteHealthReportRequest {
                    backend_id: String::from("backend-1"),
                    healthy: false,
                    observed_latency_ms: Some(15_000),
                    message: Some(String::from("probe timeout")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let evaluated = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("locality-health.example.com"),
                    protocol: Some(String::from("https")),
                    source_identity: None,
                    client_ip: Some(String::from("198.51.100.71")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: Some(String::from("us-east-1")),
                    preferred_cell: Some(String::from("use1-edge-a")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(evaluated.admitted);
        assert_eq!(evaluated.selected_backend_id.as_deref(), Some("backend-2"));

        let audits = list_decision_audits(&service).await;
        assert_eq!(audits.len(), 1);
        let audit = &audits[0];
        assert_eq!(audit.selected_locality, "fallback:any_healthy");
        assert_eq!(audit.selected_canary_pool, "unpartitioned");
        assert!(audit.steering_denial_reason.is_none());
    }

    #[tokio::test]
    async fn evaluate_route_denies_when_locality_fallback_is_disabled() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("strict-locality.example.com"),
                    target: None,
                    backends: vec![super::CreateRouteBackendRequest {
                        target: String::from("http://10.0.0.61:8080"),
                        weight: Some(1),
                        region: Some(String::from("us-east-1")),
                        cell: Some(String::from("use1-edge-a")),
                        canary: false,
                    }],
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: Some(SteeringPolicy {
                        locality_mode: LocalityMode::Region,
                        fallback_to_any_healthy: false,
                        canary: CanarySteeringPolicy::default(),
                    }),
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let denied = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("strict-locality.example.com"),
                    protocol: Some(String::from("https")),
                    source_identity: None,
                    client_ip: Some(String::from("198.51.100.72")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: Some(String::from("eu-central-1")),
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(!denied.admitted);
        assert_eq!(
            denied.reason,
            "route steering policy found no backend candidates for preferred locality"
        );
    }

    #[tokio::test]
    async fn evaluate_route_routes_canary_traffic_to_marked_backends() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("canary.example.com"),
                    target: None,
                    backends: vec![
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.71:8080"),
                            weight: Some(1),
                            region: None,
                            cell: None,
                            canary: false,
                        },
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.72:8080"),
                            weight: Some(1),
                            region: None,
                            cell: None,
                            canary: true,
                        },
                    ],
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: Some(SteeringPolicy {
                        locality_mode: LocalityMode::None,
                        fallback_to_any_healthy: true,
                        canary: CanarySteeringPolicy {
                            traffic_percent: 100,
                        },
                    }),
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let evaluated = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("canary.example.com"),
                    protocol: Some(String::from("https")),
                    source_identity: None,
                    client_ip: Some(String::from("198.51.100.73")),
                    session_key: Some(String::from("tenant-a")),
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(evaluated.admitted);
        assert_eq!(evaluated.selected_backend_id.as_deref(), Some("backend-2"));
    }

    #[tokio::test]
    async fn flow_audit_persists_steering_evidence_across_reopen() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        {
            let service = IngressService::open(temp.path())
                .await
                .unwrap_or_else(|error| panic!("{error}"));

            service
                .create_route(
                    CreateRouteRequest {
                        hostname: String::from("persist-allow.example.com"),
                        target: None,
                        backends: vec![
                            super::CreateRouteBackendRequest {
                                target: String::from("http://10.0.0.91:8080"),
                                weight: Some(1),
                                region: Some(String::from("us-east-1")),
                                cell: Some(String::from("use1-edge-a")),
                                canary: false,
                            },
                            super::CreateRouteBackendRequest {
                                target: String::from("http://10.0.0.92:8080"),
                                weight: Some(1),
                                region: Some(String::from("us-east-1")),
                                cell: Some(String::from("use1-edge-a")),
                                canary: true,
                            },
                        ],
                        protocol: String::from("https"),
                        sticky_sessions: false,
                        tls_mode: String::from("strict_https"),
                        publication: None,
                        health_check: None,
                        retry_policy: None,
                        circuit_breaker: None,
                        timeout_policy: None,
                        header_policy: None,
                        compression_policy: None,
                        rate_limit_policy: None,
                        sticky_session_policy: None,
                        service_identity_policy: None,
                        steering_policy: Some(SteeringPolicy {
                            locality_mode: LocalityMode::Cell,
                            fallback_to_any_healthy: true,
                            canary: CanarySteeringPolicy {
                                traffic_percent: 100,
                            },
                        }),
                        change_request_id: Some(
                            seed_governance_change_request(&service, "approved").await,
                        ),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));

            let allowed = service
                .evaluate_route_internal(
                    EvaluateRouteRequest {
                        hostname: String::from("persist-allow.example.com"),
                        protocol: Some(String::from("https")),
                        source_identity: None,
                        client_ip: Some(String::from("198.51.100.177")),
                        session_key: Some(String::from("tenant-persist")),
                        request_path: None,
                        source_country: None,
                        waf_score: None,
                        bot_score: None,
                        ddos_suspected: None,
                        private_network_id: None,
                        preferred_region: Some(String::from("us-east-1")),
                        preferred_cell: Some(String::from("use1-edge-a")),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert!(allowed.admitted);
            assert_eq!(allowed.selected_backend_id.as_deref(), Some("backend-2"));

            service
                .create_route(
                    CreateRouteRequest {
                        hostname: String::from("persist-deny.example.com"),
                        target: None,
                        backends: vec![super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.93:8080"),
                            weight: Some(1),
                            region: Some(String::from("us-east-1")),
                            cell: Some(String::from("use1-edge-a")),
                            canary: false,
                        }],
                        protocol: String::from("https"),
                        sticky_sessions: false,
                        tls_mode: String::from("strict_https"),
                        publication: None,
                        health_check: None,
                        retry_policy: None,
                        circuit_breaker: None,
                        timeout_policy: None,
                        header_policy: None,
                        compression_policy: None,
                        rate_limit_policy: None,
                        sticky_session_policy: None,
                        service_identity_policy: None,
                        steering_policy: Some(SteeringPolicy {
                            locality_mode: LocalityMode::Region,
                            fallback_to_any_healthy: false,
                            canary: CanarySteeringPolicy::default(),
                        }),
                        change_request_id: Some(
                            seed_governance_change_request(&service, "approved").await,
                        ),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));

            let denied = service
                .evaluate_route_internal(
                    EvaluateRouteRequest {
                        hostname: String::from("persist-deny.example.com"),
                        protocol: Some(String::from("https")),
                        source_identity: None,
                        client_ip: Some(String::from("198.51.100.178")),
                        session_key: None,
                        request_path: None,
                        source_country: None,
                        waf_score: None,
                        bot_score: None,
                        ddos_suspected: None,
                        private_network_id: None,
                        preferred_region: Some(String::from("eu-central-1")),
                        preferred_cell: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert!(!denied.admitted);
            assert_eq!(
                denied.reason,
                "route steering policy found no backend candidates for preferred locality"
            );
        }

        let reopened = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let audits: Vec<super::IngressDecisionAudit> = parse_api_body(
            reopened
                .list_flow_audit(&BTreeMap::new())
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(audits.len(), 2);

        let allow_audit = audits
            .iter()
            .find(|audit| audit.hostname == "persist-allow.example.com")
            .unwrap_or_else(|| panic!("missing persisted allow audit"));
        assert_eq!(allow_audit.selected_locality, "cell:use1-edge-a");
        assert_eq!(allow_audit.selected_canary_pool, "canary");
        assert!(allow_audit.steering_denial_reason.is_none());

        let deny_audit = audits
            .iter()
            .find(|audit| audit.hostname == "persist-deny.example.com")
            .unwrap_or_else(|| panic!("missing persisted deny audit"));
        assert_eq!(
            deny_audit.steering_denial_reason.as_deref(),
            Some("route steering policy found no backend candidates for preferred locality")
        );
        assert_eq!(deny_audit.selected_locality, "region:eu-central-1");
        assert_eq!(deny_audit.selected_canary_pool, "not_evaluated");
    }

    #[tokio::test]
    async fn half_open_circuit_prefers_canary_probe_backends() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("half-open-canary.example.com"),
                    target: None,
                    backends: vec![
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.81:8080"),
                            weight: Some(1),
                            region: None,
                            cell: None,
                            canary: false,
                        },
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.82:8080"),
                            weight: Some(1),
                            region: None,
                            cell: None,
                            canary: true,
                        },
                    ],
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: Some(CircuitBreakerPolicy {
                        failure_threshold: 1,
                        success_threshold: 1,
                        open_interval_seconds: 1,
                    }),
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: Some(SteeringPolicy {
                        locality_mode: LocalityMode::None,
                        fallback_to_any_healthy: true,
                        canary: CanarySteeringPolicy { traffic_percent: 0 },
                    }),
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_body = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let route: super::RouteRecord =
            serde_json::from_slice(&created_body).unwrap_or_else(|error| panic!("{error}"));

        service
            .record_circuit_event(
                route.id.as_str(),
                RouteCircuitEventRequest {
                    success: false,
                    reason: Some(String::from("backend failure")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored = service
            .routes
            .get(route.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing route"));
        let mut route_record = stored.value;
        let opened_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(2);
        route_record.policy_state.opened_at = Some(opened_at);
        route_record.policy_state.last_transition_at = opened_at;
        service
            .routes
            .upsert(route.id.as_str(), route_record, Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let evaluated = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("half-open-canary.example.com"),
                    protocol: Some(String::from("https")),
                    source_identity: None,
                    client_ip: Some(String::from("198.51.100.74")),
                    session_key: Some(String::from("tenant-b")),
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(evaluated.admitted);
        assert_eq!(evaluated.selected_backend_id.as_deref(), Some("backend-2"));
    }

    #[tokio::test]
    async fn half_open_circuit_denies_without_healthy_canary_probe_backends() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("half-open-canary-deny.example.com"),
                    target: None,
                    backends: vec![
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.83:8080"),
                            weight: Some(1),
                            region: None,
                            cell: None,
                            canary: false,
                        },
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.84:8080"),
                            weight: Some(1),
                            region: None,
                            cell: None,
                            canary: true,
                        },
                    ],
                    protocol: String::from("https"),
                    sticky_sessions: false,
                    tls_mode: String::from("strict_https"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: Some(CircuitBreakerPolicy {
                        failure_threshold: 1,
                        success_threshold: 1,
                        open_interval_seconds: 1,
                    }),
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: Some(SteeringPolicy {
                        locality_mode: LocalityMode::None,
                        fallback_to_any_healthy: true,
                        canary: CanarySteeringPolicy { traffic_percent: 0 },
                    }),
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_body = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let route: super::RouteRecord =
            serde_json::from_slice(&created_body).unwrap_or_else(|error| panic!("{error}"));

        service
            .report_backend_health(
                route.id.as_str(),
                RouteHealthReportRequest {
                    backend_id: String::from("backend-2"),
                    healthy: false,
                    observed_latency_ms: Some(15_000),
                    message: Some(String::from("probe timeout")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .record_circuit_event(
                route.id.as_str(),
                RouteCircuitEventRequest {
                    success: false,
                    reason: Some(String::from("backend failure")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored = service
            .routes
            .get(route.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing route"));
        let mut route_record = stored.value;
        let opened_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(2);
        route_record.policy_state.opened_at = Some(opened_at);
        route_record.policy_state.last_transition_at = opened_at;
        service
            .routes
            .upsert(route.id.as_str(), route_record, Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let denied = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("half-open-canary-deny.example.com"),
                    protocol: Some(String::from("https")),
                    source_identity: None,
                    client_ip: Some(String::from("198.51.100.76")),
                    session_key: Some(String::from("tenant-c")),
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(!denied.admitted);
        assert_eq!(
            denied.reason,
            "route circuit breaker is half-open and no healthy canary probe backends are available"
        );

        let audits = list_decision_audits(&service).await;
        assert_eq!(audits.len(), 1);
        let audit = &audits[0];
        assert_eq!(audit.selected_locality, "not_evaluated");
        assert_eq!(audit.selected_canary_pool, "canary_probe");
        assert_eq!(
            audit.steering_denial_reason.as_deref(),
            Some(
                "route circuit breaker is half-open and no healthy canary probe backends are available"
            )
        );
    }

    #[tokio::test]
    async fn route_rate_limit_denies_after_budget_exhausted() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("ratelimit.example.com"),
                    target: Some(String::from("http://127.0.0.1:8080")),
                    backends: Vec::new(),
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: Some(super::RateLimitPolicy {
                        requests_per_minute: 2,
                        burst: 0,
                    }),
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        for _ in 0..2 {
            let admitted = service
                .evaluate_route_internal(
                    EvaluateRouteRequest {
                        hostname: String::from("ratelimit.example.com"),
                        protocol: None,
                        source_identity: None,
                        client_ip: Some(String::from("198.51.100.5")),
                        session_key: None,
                        request_path: None,
                        source_country: None,
                        waf_score: None,
                        bot_score: None,
                        ddos_suspected: None,
                        private_network_id: None,
                        preferred_region: None,
                        preferred_cell: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            assert!(admitted.admitted);
        }

        let denied = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("ratelimit.example.com"),
                    protocol: None,
                    source_identity: None,
                    client_ip: Some(String::from("198.51.100.5")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!denied.admitted);
        assert_eq!(denied.reason, "route rate limit exceeded");
    }

    #[tokio::test]
    async fn sticky_session_hash_is_stable_for_same_session_key() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("sticky.example.com"),
                    target: None,
                    backends: vec![
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.21:8080"),
                            weight: Some(1),
                            region: None,
                            cell: None,
                            canary: false,
                        },
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.22:8080"),
                            weight: Some(1),
                            region: None,
                            cell: None,
                            canary: false,
                        },
                    ],
                    protocol: String::from("https"),
                    sticky_sessions: true,
                    tls_mode: String::from("strict_https"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: Some(StickySessionPolicy {
                        enabled: true,
                        cookie_name: String::from("route_sticky"),
                        ttl_seconds: 1800,
                    }),
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("sticky.example.com"),
                    protocol: Some(String::from("https")),
                    source_identity: None,
                    client_ip: None,
                    session_key: Some(String::from("session-abc")),
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("sticky.example.com"),
                    protocol: Some(String::from("https")),
                    source_identity: None,
                    client_ip: None,
                    session_key: Some(String::from("session-abc")),
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first.selected_backend, second.selected_backend);
    }

    #[tokio::test]
    async fn backend_health_report_removes_unhealthy_backend_from_selection() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("health.example.com"),
                    target: None,
                    backends: vec![
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.30:8080"),
                            weight: Some(1),
                            region: None,
                            cell: None,
                            canary: false,
                        },
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.31:8080"),
                            weight: Some(1),
                            region: None,
                            cell: None,
                            canary: false,
                        },
                    ],
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_body = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let route: super::RouteRecord =
            serde_json::from_slice(&created_body).unwrap_or_else(|error| panic!("{error}"));
        let unhealthy_backend_id = route
            .backends
            .first()
            .map(|backend| backend.id.clone())
            .unwrap_or_else(|| panic!("missing backend"));

        service
            .report_backend_health(
                route.id.as_str(),
                RouteHealthReportRequest {
                    backend_id: unhealthy_backend_id.clone(),
                    healthy: false,
                    observed_latency_ms: Some(20_000),
                    message: Some(String::from("probe timeout")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let evaluated = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("health.example.com"),
                    protocol: Some(String::from("http")),
                    source_identity: None,
                    client_ip: Some(String::from("203.0.113.25")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(evaluated.admitted);
        assert_ne!(evaluated.selected_backend_id, Some(unhealthy_backend_id));
    }

    #[tokio::test]
    async fn evaluate_route_denies_when_all_backends_are_unhealthy() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("all-unhealthy.example.com"),
                    target: None,
                    backends: vec![
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.32:8080"),
                            weight: Some(1),
                            region: None,
                            cell: None,
                            canary: false,
                        },
                        super::CreateRouteBackendRequest {
                            target: String::from("http://10.0.0.33:8080"),
                            weight: Some(1),
                            region: None,
                            cell: None,
                            canary: false,
                        },
                    ],
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_body = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let route: super::RouteRecord =
            serde_json::from_slice(&created_body).unwrap_or_else(|error| panic!("{error}"));

        for backend in &route.backends {
            service
                .report_backend_health(
                    route.id.as_str(),
                    RouteHealthReportRequest {
                        backend_id: backend.id.clone(),
                        healthy: false,
                        observed_latency_ms: Some(20_000),
                        message: Some(String::from("probe timeout")),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let denied = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("all-unhealthy.example.com"),
                    protocol: Some(String::from("http")),
                    source_identity: None,
                    client_ip: Some(String::from("203.0.113.26")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(!denied.admitted);
        assert_eq!(denied.reason, "route has no healthy backends");
        assert!(denied.selected_backend_id.is_none());

        let audits = list_decision_audits(&service).await;
        assert_eq!(audits.len(), 1);
        let audit = &audits[0];
        assert_eq!(audit.selected_locality, "not_evaluated");
        assert_eq!(audit.selected_canary_pool, "not_evaluated");
        assert_eq!(
            audit.steering_denial_reason.as_deref(),
            Some("route has no healthy backends")
        );
    }

    #[tokio::test]
    async fn circuit_breaker_opens_after_threshold() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("circuit.example.com"),
                    target: Some(String::from("http://127.0.0.1:18080")),
                    backends: Vec::new(),
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: Some(CircuitBreakerPolicy {
                        failure_threshold: 2,
                        success_threshold: 1,
                        open_interval_seconds: 60,
                    }),
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_body = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let route: super::RouteRecord =
            serde_json::from_slice(&created_body).unwrap_or_else(|error| panic!("{error}"));

        service
            .record_circuit_event(
                route.id.as_str(),
                RouteCircuitEventRequest {
                    success: false,
                    reason: Some(String::from("backend 5xx")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .record_circuit_event(
                route.id.as_str(),
                RouteCircuitEventRequest {
                    success: false,
                    reason: Some(String::from("backend timeout")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored = service
            .routes
            .get(route.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing route"));
        assert_eq!(stored.value.policy_state.circuit_state, CircuitState::Open);

        let denied = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("circuit.example.com"),
                    protocol: Some(String::from("http")),
                    source_identity: None,
                    client_ip: Some(String::from("198.51.100.22")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!denied.admitted);
        assert_eq!(denied.reason, "route circuit breaker is open");
    }

    #[tokio::test]
    async fn create_route_rejects_unknown_protocol() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("invalid.example.com"),
                    target: Some(String::from("http://127.0.0.1:8080")),
                    backends: Vec::new(),
                    protocol: String::from("bogus"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .expect_err("invalid protocol should be rejected");
        assert!(error.to_string().contains("protocol must be one of"));
    }

    #[tokio::test]
    async fn create_route_rejects_unsupported_backend_target_scheme() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("invalid-target.example.com"),
                    target: Some(String::from("ftp://127.0.0.1:8080")),
                    backends: Vec::new(),
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: None,
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .expect_err("unsupported backend target scheme should be rejected");
        assert!(
            error
                .to_string()
                .contains("backend target must start with http://")
        );
    }

    #[tokio::test]
    async fn rate_limit_cleanup_discards_stale_buckets() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let policy = super::RateLimitPolicy {
            requests_per_minute: 1,
            burst: 0,
        };

        assert!(service.consume_rate_limit("route-a", &policy, 60).await);
        assert!(service.consume_rate_limit("route-b", &policy, 60).await);
        assert_eq!(service.rate_counters.lock().await.len(), 2);

        assert!(service.consume_rate_limit("route-c", &policy, 180).await);
        let counters = service.rate_counters.lock().await;
        assert_eq!(counters.len(), 1);
        assert!(counters.contains_key("route-c"));
    }

    #[tokio::test]
    async fn circuit_breaker_recovers_from_half_open_success() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IngressService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .create_route(
                CreateRouteRequest {
                    hostname: String::from("half-open.example.com"),
                    target: Some(String::from("http://127.0.0.1:18080")),
                    backends: Vec::new(),
                    protocol: String::from("http"),
                    sticky_sessions: false,
                    tls_mode: String::from("offload"),
                    publication: None,
                    health_check: None,
                    retry_policy: None,
                    circuit_breaker: Some(CircuitBreakerPolicy {
                        failure_threshold: 1,
                        success_threshold: 1,
                        open_interval_seconds: 1,
                    }),
                    timeout_policy: None,
                    header_policy: None,
                    compression_policy: None,
                    rate_limit_policy: None,
                    sticky_session_policy: None,
                    service_identity_policy: None,
                    steering_policy: None,
                    change_request_id: Some(
                        seed_governance_change_request(&service, "approved").await,
                    ),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_body = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let route: super::RouteRecord =
            serde_json::from_slice(&created_body).unwrap_or_else(|error| panic!("{error}"));

        service
            .record_circuit_event(
                route.id.as_str(),
                RouteCircuitEventRequest {
                    success: false,
                    reason: Some(String::from("backend failure")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored = service
            .routes
            .get(route.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing route"));
        assert_eq!(stored.value.policy_state.circuit_state, CircuitState::Open);

        let mut route_record = stored.value;
        let opened_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(2);
        route_record.policy_state.opened_at = Some(opened_at);
        route_record.policy_state.last_transition_at = opened_at;
        service
            .routes
            .upsert(route.id.as_str(), route_record, Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let evaluated = service
            .evaluate_route_internal(
                EvaluateRouteRequest {
                    hostname: String::from("half-open.example.com"),
                    protocol: Some(String::from("http")),
                    source_identity: None,
                    client_ip: Some(String::from("198.51.100.44")),
                    session_key: None,
                    request_path: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                    private_network_id: None,
                    preferred_region: None,
                    preferred_cell: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(evaluated.admitted);

        let half_open = service
            .routes
            .get(route.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing route"));
        assert_eq!(
            half_open.value.policy_state.circuit_state,
            CircuitState::HalfOpen
        );

        service
            .record_circuit_event(
                route.id.as_str(),
                RouteCircuitEventRequest {
                    success: true,
                    reason: Some(String::from("probe succeeded")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let closed = service
            .routes
            .get(route.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing route"));
        assert_eq!(
            closed.value.policy_state.circuit_state,
            CircuitState::Closed
        );
    }
}
