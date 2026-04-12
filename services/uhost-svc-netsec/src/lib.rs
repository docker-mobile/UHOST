//! Network security and private connectivity service.
//!
//! This bounded context owns deny-by-default policy evaluation, egress controls,
//! private network declarations, and flow-level audit evidence. It is designed
//! to run in all-in-one mode with file-backed durability while exposing stable
//! contracts that can be lifted to distributed policy engines later.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use http::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uhost_api::{ApiBody, json_response, parse_json, parse_query, path_segments};
use uhost_core::{PlatformError, RequestContext, Result, sha256_hex};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{AuditLog, DocumentStore, DurableOutbox};
use uhost_types::{
    AuditActor, AuditId, ChangeRequestId, EgressRuleId, EventHeader, EventPayload, FlowAuditId,
    GovernanceChangeAuthorization, GovernanceRequestProvenance, IpSetId, NatGatewayId, NetPolicyId,
    NextHopId, OwnershipScope, PeeringConnectionId, PlatformEvent, PolicyId, PrivateNetworkId,
    PrivateRouteId, ResourceMetadata, RouteTableId, ServiceConnectAttachmentId, ServiceEvent,
    ServiceIdentityId, SubnetId, TransitAttachmentId, VpnConnectionId,
};

const GOVERNANCE_CHANGE_REQUEST_HEADER: &str = "x-uhost-change-request-id";

/// One policy rule that may allow or deny traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetsecRule {
    /// Relative priority. Lower values are evaluated first.
    pub priority: u16,
    /// `allow` or `deny`.
    pub action: String,
    /// `ingress` or `egress`.
    pub direction: String,
    /// `tcp`, `udp`, `http`, `https`, `any`.
    pub protocol: String,
    /// CIDR expression or `ipset:<id>`.
    pub cidr: String,
    /// Inclusive lower bound of destination port.
    pub port_start: u16,
    /// Inclusive upper bound of destination port.
    pub port_end: u16,
    /// Whether a non-empty source identity is required.
    pub require_identity: bool,
}

/// Top-level policy record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetsecPolicy {
    /// Policy identifier.
    pub id: NetPolicyId,
    /// Operator-visible policy name.
    pub name: String,
    /// Selector labels used to target workloads and projects.
    pub selector: BTreeMap<String, String>,
    /// Default action when no rule matches (`deny` by default).
    pub default_action: String,
    /// mTLS enforcement mode (`strict` or `permissive`).
    pub mtls_mode: String,
    /// Ordered policy rules.
    pub rules: Vec<NetsecRule>,
    /// Shared resource metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the policy mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// Reusable IP set for policy references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpSetRecord {
    /// IP set identifier.
    pub id: IpSetId,
    /// Human-readable name.
    pub name: String,
    /// IPv4 CIDRs included in this set.
    pub cidrs: Vec<String>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the IP-set mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// Private network declaration and attachment metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateNetworkRecord {
    /// Private network identifier.
    pub id: PrivateNetworkId,
    /// Network name.
    pub name: String,
    /// Address space in CIDR form.
    pub cidr: String,
    /// Attached identity selectors.
    pub attachments: Vec<String>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the network mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// One subnet carved from a private network CIDR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubnetRecord {
    /// Subnet identifier.
    pub id: SubnetId,
    /// Parent private network identifier.
    pub private_network_id: PrivateNetworkId,
    /// Human-readable subnet name.
    pub name: String,
    /// Concrete subnet CIDR.
    pub cidr: String,
    /// Explicit route table association when one exists.
    pub route_table_id: Option<RouteTableId>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the subnet mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// One route table attached to a private network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTableRecord {
    /// Route table identifier.
    pub id: RouteTableId,
    /// Parent private network identifier.
    pub private_network_id: PrivateNetworkId,
    /// Human-readable route table name.
    pub name: String,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the route-table mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// One route next hop target scoped to a private network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextHopRecord {
    /// Next-hop identifier.
    pub id: NextHopId,
    /// Parent private network identifier.
    pub private_network_id: PrivateNetworkId,
    /// Human-readable next-hop name.
    pub name: String,
    /// Next-hop kind (`local`, `service_identity`, `ip_address`, or `blackhole`).
    pub kind: String,
    /// Kind-specific normalized target.
    pub target: Option<String>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the next-hop mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// One private route attached to a route table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRouteRecord {
    /// Private route identifier.
    pub id: PrivateRouteId,
    /// Parent private network identifier.
    pub private_network_id: PrivateNetworkId,
    /// Parent route table identifier.
    pub route_table_id: RouteTableId,
    /// Destination CIDR.
    pub destination: String,
    /// Referenced next-hop identifier.
    pub next_hop_id: NextHopId,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the private-route mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// One east-west service-connect attachment joining a route and service identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceConnectAttachmentRecord {
    /// Stable service-connect attachment identifier.
    pub id: ServiceConnectAttachmentId,
    /// Parent private network identifier.
    pub private_network_id: PrivateNetworkId,
    /// Referenced private route identifier.
    pub private_route_id: PrivateRouteId,
    /// Referenced route table identifier.
    pub route_table_id: RouteTableId,
    /// Attached service identity identifier.
    pub service_identity_id: ServiceIdentityId,
    /// Attached service identity subject for operator readability.
    pub service_identity_subject: String,
    /// Destination CIDR carried by the linked private route.
    pub destination: String,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the service-connect mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// One NAT gateway attached to a private network and tenant/cell boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatGatewayRecord {
    /// NAT gateway identifier.
    pub id: NatGatewayId,
    /// Parent private network identifier.
    pub private_network_id: PrivateNetworkId,
    /// Human-readable NAT gateway name.
    pub name: String,
    /// Tenant that owns this gateway.
    pub tenant_id: String,
    /// Cell responsible for the gateway placement.
    pub cell: String,
    /// Public egress IPv4 address.
    pub public_ip: String,
    /// Optional subnet where the gateway lands.
    pub subnet_id: Option<SubnetId>,
    /// Route tables that should target this gateway.
    pub route_table_ids: Vec<RouteTableId>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the NAT-gateway mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// One transit attachment connecting a private network to a transit network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitAttachmentRecord {
    /// Transit attachment identifier.
    pub id: TransitAttachmentId,
    /// Parent private network identifier.
    pub private_network_id: PrivateNetworkId,
    /// Human-readable transit attachment name.
    pub name: String,
    /// Tenant that owns the local attachment.
    pub tenant_id: String,
    /// Cell responsible for the local attachment.
    pub cell: String,
    /// Transit private network identifier.
    pub transit_private_network_id: PrivateNetworkId,
    /// Tenant that owns the transit side.
    pub transit_tenant_id: String,
    /// Cell that hosts the transit side.
    pub transit_cell: String,
    /// Route tables that should advertise this attachment.
    pub route_table_ids: Vec<RouteTableId>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the transit-attachment mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// One VPN connection declared from a private network to remote CIDRs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnConnectionRecord {
    /// VPN connection identifier.
    pub id: VpnConnectionId,
    /// Parent private network identifier.
    pub private_network_id: PrivateNetworkId,
    /// Human-readable VPN connection name.
    pub name: String,
    /// Tenant that owns this VPN connection.
    pub tenant_id: String,
    /// Cell responsible for the local tunnel endpoint.
    pub cell: String,
    /// Remote gateway IPv4 address.
    pub gateway_address: String,
    /// Remote CIDRs advertised over the tunnel.
    pub remote_cidrs: Vec<String>,
    /// Route tables that should target this VPN connection.
    pub route_table_ids: Vec<RouteTableId>,
    /// Routing mode (`static` or `bgp`).
    pub routing_mode: String,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the VPN-connection mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// One peering connection between two private networks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeeringConnectionRecord {
    /// Peering connection identifier.
    pub id: PeeringConnectionId,
    /// Parent private network identifier.
    pub private_network_id: PrivateNetworkId,
    /// Human-readable peering connection name.
    pub name: String,
    /// Tenant that owns the local peering side.
    pub tenant_id: String,
    /// Cell responsible for the local peering side.
    pub cell: String,
    /// Peer private network identifier.
    pub peer_private_network_id: PrivateNetworkId,
    /// Tenant that owns the peer side.
    pub peer_tenant_id: String,
    /// Cell that hosts the peer side.
    pub peer_cell: String,
    /// Route tables that should advertise the peering.
    pub route_table_ids: Vec<RouteTableId>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the peering mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// Service identity registered for mTLS and private-network policy enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceIdentityRecord {
    /// Service identity identifier.
    pub id: ServiceIdentityId,
    /// Stable identity subject string (`svc:api`, `svc:worker`, etc.).
    pub subject: String,
    /// Fingerprint of the mTLS certificate expected for this identity.
    pub mtls_cert_fingerprint: String,
    /// Identity labels that can be used by downstream policy engines.
    pub labels: BTreeMap<String, String>,
    /// Explicit private network entitlements.
    pub allowed_private_networks: Vec<PrivateNetworkId>,
    /// Whether this identity is currently active.
    pub enabled: bool,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the service-identity mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// Explicit egress control entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRuleRecord {
    /// Egress rule identifier.
    pub id: EgressRuleId,
    /// `cidr` or `hostname`.
    pub target_kind: String,
    /// Value for the selected kind.
    pub target_value: String,
    /// `allow` or `deny`.
    pub action: String,
    /// Human explanation captured for audits.
    pub reason: String,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the egress mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// Flow-level audit evidence produced by each policy check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowAuditRecord {
    /// Flow audit identifier.
    pub id: FlowAuditId,
    /// Request source identity string when provided.
    pub source_identity: Option<String>,
    /// Destination IP.
    pub destination: String,
    /// Requested protocol.
    pub protocol: String,
    /// Requested destination port.
    pub port: u16,
    /// Final verdict (`allow` or `deny`).
    pub verdict: String,
    /// Policy that made the decision, when one matched.
    pub policy_id: Option<NetPolicyId>,
    /// Inspection profile that participated in this decision.
    pub inspection_profile_id: Option<PolicyId>,
    /// Inspection-level reason when present.
    pub inspection_reason: Option<String>,
    /// Source country hint used by geo filters.
    pub source_country: Option<String>,
    /// WAF score observed for this request.
    pub waf_score: Option<u16>,
    /// Bot score observed for this request.
    pub bot_score: Option<u16>,
    /// Whether DDoS suspicion flag was provided.
    pub ddos_suspected: bool,
    /// Operator-readable reason for the decision.
    pub reason: String,
    /// Evaluation timestamp.
    pub observed_at: OffsetDateTime,
}

/// External inspection policy profile used for geo/WAF/bot/DDoS hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectionProfileRecord {
    /// Inspection profile identifier.
    pub id: PolicyId,
    /// Operator-visible profile name.
    pub name: String,
    /// Blocked source country codes (ISO-3166 alpha-2).
    pub blocked_countries: Vec<String>,
    /// Minimum accepted WAF score.
    pub min_waf_score: u16,
    /// Maximum accepted bot score.
    pub max_bot_score: u16,
    /// DDoS mode (`monitor`, `mitigate`, `block`).
    pub ddos_mode: String,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the inspection-profile mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreatePolicyRequest {
    name: String,
    selector: BTreeMap<String, String>,
    default_action: Option<String>,
    mtls_mode: Option<String>,
    rules: Vec<NetsecRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateIpSetRequest {
    name: String,
    cidrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreatePrivateNetworkRequest {
    name: String,
    cidr: String,
    attachments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateSubnetRequest {
    name: String,
    cidr: String,
    route_table_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateRouteTableRequest {
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateNextHopRequest {
    name: String,
    kind: String,
    target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreatePrivateRouteRequest {
    destination: String,
    next_hop_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateServiceConnectAttachmentRequest {
    service_identity: String,
    private_route_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateNatGatewayRequest {
    name: String,
    #[serde(default)]
    tenant_id: Option<String>,
    cell: String,
    public_ip: String,
    #[serde(default)]
    subnet_id: Option<String>,
    #[serde(default)]
    route_table_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateTransitAttachmentRequest {
    name: String,
    #[serde(default)]
    tenant_id: Option<String>,
    cell: String,
    transit_private_network_id: String,
    transit_tenant_id: String,
    transit_cell: String,
    #[serde(default)]
    route_table_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateVpnConnectionRequest {
    name: String,
    #[serde(default)]
    tenant_id: Option<String>,
    cell: String,
    gateway_address: String,
    remote_cidrs: Vec<String>,
    #[serde(default)]
    route_table_ids: Vec<String>,
    #[serde(default)]
    routing_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreatePeeringConnectionRequest {
    name: String,
    #[serde(default)]
    tenant_id: Option<String>,
    cell: String,
    peer_private_network_id: String,
    peer_tenant_id: String,
    peer_cell: String,
    #[serde(default)]
    route_table_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateServiceIdentityRequest {
    subject: String,
    mtls_cert_fingerprint: String,
    labels: BTreeMap<String, String>,
    allowed_private_networks: Vec<String>,
    enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateEgressRuleRequest {
    target_kind: String,
    target_value: String,
    action: String,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateInspectionProfileRequest {
    name: String,
    blocked_countries: Vec<String>,
    min_waf_score: Option<u16>,
    max_bot_score: Option<u16>,
    ddos_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PolicyVerifyRequest {
    source_identity: Option<String>,
    destination: String,
    protocol: String,
    port: u16,
    labels: BTreeMap<String, String>,
    inspection_profile_id: Option<String>,
    source_country: Option<String>,
    waf_score: Option<u16>,
    bot_score: Option<u16>,
    ddos_suspected: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PolicyVerifyResponse {
    verdict: String,
    reason: String,
    policy_id: Option<String>,
    flow_audit_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct FlowAuditQuery {
    verdict: Option<String>,
    source_identity: Option<String>,
    destination: Option<String>,
    protocol: Option<String>,
    policy_id: Option<String>,
    inspection_profile_id: Option<String>,
    since: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
    limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FlowAuditSummaryCounter {
    key: String,
    count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FlowAuditSummaryResponse {
    total: usize,
    allow: usize,
    deny: usize,
    top_reasons: Vec<FlowAuditSummaryCounter>,
    top_destinations: Vec<FlowAuditSummaryCounter>,
    top_source_identities: Vec<FlowAuditSummaryCounter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NetsecSummaryResponse {
    policies: NetsecPolicySummary,
    ip_sets: NetsecIpSetSummary,
    flow_audit: NetsecFlowAuditSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NetsecPolicySummary {
    total: usize,
    total_rules: usize,
    default_actions: Vec<FlowAuditSummaryCounter>,
    mtls_modes: Vec<FlowAuditSummaryCounter>,
    rule_actions: Vec<FlowAuditSummaryCounter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NetsecIpSetSummary {
    total: usize,
    total_cidrs: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NetsecFlowAuditSummary {
    total: usize,
    allow: usize,
    deny: usize,
    severity: Vec<FlowAuditSummaryCounter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AbuseQuarantineHookRecord {
    #[serde(default)]
    subject_kind: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    state: String,
    #[serde(default = "default_true")]
    deny_network: bool,
    expires_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GovernanceChangeRequestMirror {
    id: ChangeRequestId,
    state: String,
    #[serde(default, flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

/// Network security service.
#[derive(Debug, Clone)]
pub struct NetsecService {
    policies: DocumentStore<NetsecPolicy>,
    ip_sets: DocumentStore<IpSetRecord>,
    private_networks: DocumentStore<PrivateNetworkRecord>,
    subnets: DocumentStore<SubnetRecord>,
    route_tables: DocumentStore<RouteTableRecord>,
    next_hops: DocumentStore<NextHopRecord>,
    private_routes: DocumentStore<PrivateRouteRecord>,
    service_connect_attachments: DocumentStore<ServiceConnectAttachmentRecord>,
    nat_gateways: DocumentStore<NatGatewayRecord>,
    transit_attachments: DocumentStore<TransitAttachmentRecord>,
    vpn_connections: DocumentStore<VpnConnectionRecord>,
    peering_connections: DocumentStore<PeeringConnectionRecord>,
    service_identities: DocumentStore<ServiceIdentityRecord>,
    egress_rules: DocumentStore<EgressRuleRecord>,
    inspection_profiles: DocumentStore<InspectionProfileRecord>,
    flow_audit: DocumentStore<FlowAuditRecord>,
    abuse_quarantines: DocumentStore<AbuseQuarantineHookRecord>,
    governance_change_requests: DocumentStore<GovernanceChangeRequestMirror>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    state_root: PathBuf,
}

impl NetsecService {
    /// Open netsec state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("netsec");
        let abuse_quarantine_path = state_root.as_ref().join("abuse").join("quarantines.json");
        Ok(Self {
            policies: DocumentStore::open(root.join("policies.json")).await?,
            ip_sets: DocumentStore::open(root.join("ip_sets.json")).await?,
            private_networks: DocumentStore::open(root.join("private_networks.json")).await?,
            subnets: DocumentStore::open(root.join("subnets.json")).await?,
            route_tables: DocumentStore::open(root.join("route_tables.json")).await?,
            next_hops: DocumentStore::open(root.join("next_hops.json")).await?,
            private_routes: DocumentStore::open(root.join("routes.json")).await?,
            service_connect_attachments: DocumentStore::open(
                root.join("service_connect_attachments.json"),
            )
            .await?,
            nat_gateways: DocumentStore::open(root.join("nat_gateways.json")).await?,
            transit_attachments: DocumentStore::open(root.join("transit_attachments.json")).await?,
            vpn_connections: DocumentStore::open(root.join("vpn_connections.json")).await?,
            peering_connections: DocumentStore::open(root.join("peerings.json")).await?,
            service_identities: DocumentStore::open(root.join("service_identities.json")).await?,
            egress_rules: DocumentStore::open(root.join("egress_rules.json")).await?,
            inspection_profiles: DocumentStore::open(root.join("inspection_profiles.json")).await?,
            flow_audit: DocumentStore::open(root.join("flow_audit.json")).await?,
            abuse_quarantines: DocumentStore::open(abuse_quarantine_path).await?,
            governance_change_requests: DocumentStore::open(
                state_root
                    .as_ref()
                    .join("governance")
                    .join("change_requests.json"),
            )
            .await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            state_root: root,
        })
    }

    async fn create_policy(
        &self,
        request: CreatePolicyRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_policy_authorized(request, context, None).await
    }

    async fn create_policy_authorized(
        &self,
        request: CreatePolicyRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        if request.name.trim().is_empty() {
            return Err(PlatformError::invalid("name may not be empty"));
        }

        let default_action = normalize_action(request.default_action.as_deref().unwrap_or("deny"))?;
        let mtls_mode = normalize_mtls_mode(request.mtls_mode.as_deref().unwrap_or("strict"))?;

        let mut rules = Vec::with_capacity(request.rules.len());
        for rule in request.rules {
            let normalized = NetsecRule {
                priority: rule.priority,
                action: normalize_action(&rule.action)?,
                direction: normalize_direction(&rule.direction)?,
                protocol: normalize_protocol(&rule.protocol)?,
                cidr: normalize_cidr_selector(&rule.cidr)?,
                port_start: rule.port_start,
                port_end: rule.port_end.max(rule.port_start),
                require_identity: rule.require_identity,
            };
            rules.push(normalized);
        }
        rules.sort_by_key(|rule| rule.priority);

        let id = NetPolicyId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate netsec policy id")
                .with_detail(error.to_string())
        })?;
        let mut policy = NetsecPolicy {
            id: id.clone(),
            name: request.name,
            selector: request.selector,
            default_action,
            mtls_mode,
            rules,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                policy_mutation_digest(&policy, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut policy.metadata, "netsec.mutation_digest");
            policy.change_authorization = Some(authorization.clone());
        }
        self.policies.create(id.as_str(), policy.clone()).await?;
        let mut details = serde_json::json!({
            "name": policy.name,
            "rule_count": policy.rules.len(),
            "default_action": policy.default_action,
        });
        if let Some(authorization) = policy.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "netsec.policy.created.v1",
            "netsec_policy",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &policy)
    }

    async fn create_ip_set(
        &self,
        request: CreateIpSetRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_ip_set_authorized(request, context, None).await
    }

    async fn create_ip_set_authorized(
        &self,
        request: CreateIpSetRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        if request.name.trim().is_empty() {
            return Err(PlatformError::invalid("name may not be empty"));
        }
        let mut cidrs = Vec::new();
        for raw in request.cidrs {
            let normalized = normalize_cidr_selector(&raw)?;
            if normalized.starts_with("ipset:") {
                return Err(PlatformError::invalid(
                    "ipset references are not allowed in ip sets",
                ));
            }
            cidrs.push(normalized);
        }

        let id = IpSetId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate ip set id")
                .with_detail(error.to_string())
        })?;
        let mut record = IpSetRecord {
            id: id.clone(),
            name: request.name,
            cidrs,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                ip_set_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "netsec.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.ip_sets.create(id.as_str(), record.clone()).await?;
        let mut details = serde_json::json!({ "cidr_count": record.cidrs.len() });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "netsec.ipset.created.v1",
            "ip_set",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_private_network(
        &self,
        request: CreatePrivateNetworkRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_private_network_authorized(request, context, None)
            .await
    }

    async fn create_private_network_authorized(
        &self,
        request: CreatePrivateNetworkRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        if request.name.trim().is_empty() {
            return Err(PlatformError::invalid("name may not be empty"));
        }
        let cidr = normalize_cidr_selector(&request.cidr)?;
        if cidr.starts_with("ipset:") {
            return Err(PlatformError::invalid(
                "private network cidr must be concrete",
            ));
        }

        let id = PrivateNetworkId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate private network id")
                .with_detail(error.to_string())
        })?;
        let mut record = PrivateNetworkRecord {
            id: id.clone(),
            name: request.name,
            cidr,
            attachments: request
                .attachments
                .into_iter()
                .map(|value| normalize_attachment_reference(&value))
                .collect::<Result<Vec<_>>>()?,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                private_network_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "netsec.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.private_networks
            .create(id.as_str(), record.clone())
            .await?;
        let mut details = serde_json::json!({ "attachment_count": record.attachments.len() });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "netsec.private_network.created.v1",
            "private_network",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn private_network_by_id(
        &self,
        private_network_id: &PrivateNetworkId,
    ) -> Result<PrivateNetworkRecord> {
        self.private_networks
            .get(private_network_id.as_str())
            .await?
            .filter(|record| !record.deleted)
            .map(|record| record.value)
            .ok_or_else(|| {
                PlatformError::not_found(format!(
                    "private network {} does not exist",
                    private_network_id
                ))
            })
    }

    async fn list_subnets_for_private_network(
        &self,
        private_network_id: &PrivateNetworkId,
    ) -> Result<Vec<SubnetRecord>> {
        let _ = self.private_network_by_id(private_network_id).await?;
        let mut values = self
            .subnets
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .filter(|record| record.private_network_id == *private_network_id)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn route_table_by_id(
        &self,
        private_network_id: &PrivateNetworkId,
        route_table_id: &RouteTableId,
    ) -> Result<RouteTableRecord> {
        self.route_tables
            .get(&private_network_scoped_key(
                private_network_id,
                route_table_id.as_str(),
            ))
            .await?
            .filter(|record| {
                !record.deleted && record.value.private_network_id == *private_network_id
            })
            .map(|record| record.value)
            .ok_or_else(|| {
                PlatformError::not_found(format!(
                    "route table {} does not exist in private network {}",
                    route_table_id, private_network_id
                ))
            })
    }

    async fn list_route_tables_for_private_network(
        &self,
        private_network_id: &PrivateNetworkId,
    ) -> Result<Vec<RouteTableRecord>> {
        let _ = self.private_network_by_id(private_network_id).await?;
        let mut values = self
            .route_tables
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .filter(|record| record.private_network_id == *private_network_id)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn next_hop_by_id(
        &self,
        private_network_id: &PrivateNetworkId,
        next_hop_id: &NextHopId,
    ) -> Result<NextHopRecord> {
        self.next_hops
            .get(&private_network_scoped_key(
                private_network_id,
                next_hop_id.as_str(),
            ))
            .await?
            .filter(|record| {
                !record.deleted && record.value.private_network_id == *private_network_id
            })
            .map(|record| record.value)
            .ok_or_else(|| {
                PlatformError::not_found(format!(
                    "next hop {} does not exist in private network {}",
                    next_hop_id, private_network_id
                ))
            })
    }

    async fn list_next_hops_for_private_network(
        &self,
        private_network_id: &PrivateNetworkId,
    ) -> Result<Vec<NextHopRecord>> {
        let _ = self.private_network_by_id(private_network_id).await?;
        let mut values = self
            .next_hops
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .filter(|record| record.private_network_id == *private_network_id)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn list_routes_for_route_table(
        &self,
        private_network_id: &PrivateNetworkId,
        route_table_id: &RouteTableId,
    ) -> Result<Vec<PrivateRouteRecord>> {
        let _ = self
            .route_table_by_id(private_network_id, route_table_id)
            .await?;
        let mut values = self
            .private_routes
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .filter(|record| {
                record.private_network_id == *private_network_id
                    && record.route_table_id == *route_table_id
            })
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.destination
                .cmp(&right.destination)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn private_route_by_id(
        &self,
        private_network_id: &PrivateNetworkId,
        private_route_id: &PrivateRouteId,
    ) -> Result<PrivateRouteRecord> {
        let _ = self.private_network_by_id(private_network_id).await?;
        self.private_routes
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .find(|record| {
                record.private_network_id == *private_network_id && record.id == *private_route_id
            })
            .ok_or_else(|| {
                PlatformError::not_found(format!(
                    "private route {} does not exist in private network {}",
                    private_route_id, private_network_id
                ))
            })
    }

    async fn list_service_connect_attachments_for_private_network(
        &self,
        private_network_id: &PrivateNetworkId,
    ) -> Result<Vec<ServiceConnectAttachmentRecord>> {
        let _ = self.private_network_by_id(private_network_id).await?;
        let mut values = self
            .service_connect_attachments
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .filter(|record| record.private_network_id == *private_network_id)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.service_identity_subject
                .cmp(&right.service_identity_subject)
                .then_with(|| left.destination.cmp(&right.destination))
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn subnet_by_id(
        &self,
        private_network_id: &PrivateNetworkId,
        subnet_id: &SubnetId,
    ) -> Result<SubnetRecord> {
        self.subnets
            .get(&private_network_scoped_key(
                private_network_id,
                subnet_id.as_str(),
            ))
            .await?
            .filter(|record| {
                !record.deleted && record.value.private_network_id == *private_network_id
            })
            .map(|record| record.value)
            .ok_or_else(|| {
                PlatformError::not_found(format!(
                    "subnet {} does not exist in private network {}",
                    subnet_id, private_network_id
                ))
            })
    }

    async fn list_nat_gateways_for_private_network(
        &self,
        private_network_id: &PrivateNetworkId,
    ) -> Result<Vec<NatGatewayRecord>> {
        let _ = self.private_network_by_id(private_network_id).await?;
        let mut values = self
            .nat_gateways
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .filter(|record| record.private_network_id == *private_network_id)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn list_transit_attachments_for_private_network(
        &self,
        private_network_id: &PrivateNetworkId,
    ) -> Result<Vec<TransitAttachmentRecord>> {
        let _ = self.private_network_by_id(private_network_id).await?;
        let mut values = self
            .transit_attachments
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .filter(|record| record.private_network_id == *private_network_id)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn list_vpn_connections_for_private_network(
        &self,
        private_network_id: &PrivateNetworkId,
    ) -> Result<Vec<VpnConnectionRecord>> {
        let _ = self.private_network_by_id(private_network_id).await?;
        let mut values = self
            .vpn_connections
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .filter(|record| record.private_network_id == *private_network_id)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn list_peering_connections_for_private_network(
        &self,
        private_network_id: &PrivateNetworkId,
    ) -> Result<Vec<PeeringConnectionRecord>> {
        let _ = self.private_network_by_id(private_network_id).await?;
        let mut values = self
            .peering_connections
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .filter(|record| record.private_network_id == *private_network_id)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(values)
    }

    async fn route_table_ids_for_private_network(
        &self,
        private_network_id: &PrivateNetworkId,
        values: Vec<String>,
    ) -> Result<Vec<RouteTableId>> {
        let mut route_table_ids = Vec::with_capacity(values.len());
        for raw in values {
            let route_table_id = parse_route_table_id(&raw)?;
            let _ = self
                .route_table_by_id(private_network_id, &route_table_id)
                .await?;
            if !route_table_ids.contains(&route_table_id) {
                route_table_ids.push(route_table_id);
            }
        }
        Ok(route_table_ids)
    }

    async fn service_identity_by_reference(&self, value: &str) -> Result<ServiceIdentityRecord> {
        let normalized = normalize_attachment_reference(value)?;
        if normalized.starts_with("svc:") {
            return self
                .service_identities
                .get(&normalized)
                .await?
                .filter(|record| !record.deleted)
                .map(|record| record.value)
                .ok_or_else(|| {
                    PlatformError::not_found(format!(
                        "service identity {} does not exist",
                        normalized
                    ))
                });
        }

        let identity_id = ServiceIdentityId::parse(normalized.clone()).map_err(|error| {
            PlatformError::invalid("invalid service identity reference")
                .with_detail(error.to_string())
        })?;
        self.service_identities
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .find(|record| record.id == identity_id)
            .ok_or_else(|| {
                PlatformError::not_found(format!("service identity {} does not exist", identity_id))
            })
    }

    async fn create_subnet(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreateSubnetRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_subnet_authorized(private_network_id, request, context, None)
            .await
    }

    async fn create_subnet_authorized(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreateSubnetRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        let private_network = self.private_network_by_id(private_network_id).await?;
        let name = normalize_resource_name("name", &request.name)?;
        let cidr = normalize_cidr_selector(&request.cidr)?;
        if cidr.starts_with("ipset:") {
            return Err(PlatformError::invalid("subnet cidr must be concrete"));
        }
        if !cidr_contains_cidr(&private_network.cidr, &cidr)? {
            return Err(PlatformError::invalid(
                "subnet cidr must be contained within the private network cidr",
            ));
        }

        let route_table_id = request
            .route_table_id
            .as_deref()
            .map(parse_route_table_id)
            .transpose()?;
        if let Some(route_table_id) = route_table_id.as_ref() {
            let _ = self
                .route_table_by_id(private_network_id, route_table_id)
                .await?;
        }

        let existing_subnets = self
            .list_subnets_for_private_network(private_network_id)
            .await?;
        if existing_subnets
            .iter()
            .any(|subnet| subnet.name.eq_ignore_ascii_case(&name))
        {
            return Err(PlatformError::conflict(
                "subnet name already exists in private network",
            ));
        }
        for existing in &existing_subnets {
            if cidr_ranges_overlap(&existing.cidr, &cidr)? {
                return Err(PlatformError::conflict(format!(
                    "subnet cidr overlaps existing subnet {}",
                    existing.id
                )));
            }
        }

        let id = SubnetId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate subnet id")
                .with_detail(error.to_string())
        })?;
        let mut record = SubnetRecord {
            id: id.clone(),
            private_network_id: private_network_id.clone(),
            name,
            cidr,
            route_table_id,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                subnet_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "netsec.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.subnets
            .create(
                &private_network_scoped_key(private_network_id, id.as_str()),
                record.clone(),
            )
            .await?;
        let mut details = serde_json::json!({
            "private_network_id": private_network.id,
            "cidr": record.cidr,
            "route_table_id": record.route_table_id,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "netsec.private_network.subnet.created.v1",
            "subnet",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_route_table(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreateRouteTableRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_route_table_authorized(private_network_id, request, context, None)
            .await
    }

    async fn create_route_table_authorized(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreateRouteTableRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        let _ = self.private_network_by_id(private_network_id).await?;
        let name = normalize_resource_name("name", &request.name)?;
        let existing_route_tables = self
            .list_route_tables_for_private_network(private_network_id)
            .await?;
        if existing_route_tables
            .iter()
            .any(|route_table| route_table.name.eq_ignore_ascii_case(&name))
        {
            return Err(PlatformError::conflict(
                "route table name already exists in private network",
            ));
        }

        let id = RouteTableId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate route table id")
                .with_detail(error.to_string())
        })?;
        let mut record = RouteTableRecord {
            id: id.clone(),
            private_network_id: private_network_id.clone(),
            name,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                route_table_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "netsec.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.route_tables
            .create(
                &private_network_scoped_key(private_network_id, id.as_str()),
                record.clone(),
            )
            .await?;
        let mut details = serde_json::json!({
            "private_network_id": private_network_id,
            "name": record.name,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "netsec.private_network.route_table.created.v1",
            "route_table",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_next_hop(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreateNextHopRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_next_hop_authorized(private_network_id, request, context, None)
            .await
    }

    async fn create_next_hop_authorized(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreateNextHopRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        let private_network = self.private_network_by_id(private_network_id).await?;
        let name = normalize_resource_name("name", &request.name)?;
        let kind = normalize_next_hop_kind(&request.kind)?;
        let existing_next_hops = self
            .list_next_hops_for_private_network(private_network_id)
            .await?;
        if existing_next_hops
            .iter()
            .any(|next_hop| next_hop.name.eq_ignore_ascii_case(&name))
        {
            return Err(PlatformError::conflict(
                "next hop name already exists in private network",
            ));
        }

        let target =
            match kind.as_str() {
                "local" | "blackhole" => {
                    if request
                        .target
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
                    {
                        return Err(PlatformError::invalid(format!(
                            "next hop kind `{kind}` does not accept a target"
                        )));
                    }
                    None
                }
                "ip_address" => {
                    let value = request.target.as_deref().ok_or_else(|| {
                        PlatformError::invalid("next hop target may not be empty")
                    })?;
                    Some(normalize_ipv4(value)?.to_string())
                }
                "service_identity" => {
                    let value = request.target.as_deref().ok_or_else(|| {
                        PlatformError::invalid("next hop target may not be empty")
                    })?;
                    // Route wiring is staged before the narrower service-connect
                    // attachment is created, so only identity existence is required here.
                    let service_identity = self.service_identity_by_reference(value).await?;
                    Some(service_identity.id.to_string())
                }
                _ => return Err(PlatformError::invalid("unsupported next hop kind")),
            };

        let id = NextHopId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate next hop id")
                .with_detail(error.to_string())
        })?;
        let mut record = NextHopRecord {
            id: id.clone(),
            private_network_id: private_network_id.clone(),
            name,
            kind,
            target,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                next_hop_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "netsec.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.next_hops
            .create(
                &private_network_scoped_key(private_network_id, id.as_str()),
                record.clone(),
            )
            .await?;
        let mut details = serde_json::json!({
            "private_network_id": private_network.id,
            "kind": record.kind,
            "target": record.target,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "netsec.private_network.next_hop.created.v1",
            "next_hop",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_private_route(
        &self,
        private_network_id: &PrivateNetworkId,
        route_table_id: &RouteTableId,
        request: CreatePrivateRouteRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_private_route_authorized(
            private_network_id,
            route_table_id,
            request,
            context,
            None,
        )
        .await
    }

    async fn create_private_route_authorized(
        &self,
        private_network_id: &PrivateNetworkId,
        route_table_id: &RouteTableId,
        request: CreatePrivateRouteRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        let _ = self.private_network_by_id(private_network_id).await?;
        let _ = self
            .route_table_by_id(private_network_id, route_table_id)
            .await?;
        let destination = normalize_cidr_selector(&request.destination)?;
        if destination.starts_with("ipset:") {
            return Err(PlatformError::invalid("route destination must be concrete"));
        }
        let next_hop_id = parse_next_hop_id(&request.next_hop_id)?;
        let _ = self
            .next_hop_by_id(private_network_id, &next_hop_id)
            .await?;

        let existing_routes = self
            .list_routes_for_route_table(private_network_id, route_table_id)
            .await?;
        if existing_routes
            .iter()
            .any(|route| route.destination == destination)
        {
            return Err(PlatformError::conflict(
                "route destination already exists in route table",
            ));
        }

        let id = PrivateRouteId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate private route id")
                .with_detail(error.to_string())
        })?;
        let mut record = PrivateRouteRecord {
            id: id.clone(),
            private_network_id: private_network_id.clone(),
            route_table_id: route_table_id.clone(),
            destination,
            next_hop_id,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                private_route_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "netsec.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.private_routes
            .create(
                &private_route_scoped_key(private_network_id, route_table_id, id.as_str()),
                record.clone(),
            )
            .await?;
        let mut details = serde_json::json!({
            "private_network_id": private_network_id,
            "route_table_id": route_table_id,
            "destination": record.destination,
            "next_hop_id": record.next_hop_id,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "netsec.private_network.route.created.v1",
            "private_route",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_service_connect_attachment(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreateServiceConnectAttachmentRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_service_connect_attachment_authorized(
            private_network_id,
            request,
            context,
            None,
        )
        .await
    }

    async fn create_service_connect_attachment_authorized(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreateServiceConnectAttachmentRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        let _ = self.private_network_by_id(private_network_id).await?;
        let service_identity = self
            .service_identity_by_reference(&request.service_identity)
            .await?;
        let private_route_id = parse_private_route_id(&request.private_route_id)?;
        let private_route = self
            .private_route_by_id(private_network_id, &private_route_id)
            .await?;
        let next_hop = self
            .next_hop_by_id(private_network_id, &private_route.next_hop_id)
            .await?;
        if next_hop.kind != "service_identity" {
            return Err(PlatformError::invalid(
                "service-connect attachment route must target a `service_identity` next hop",
            ));
        }
        let target_identity_id = next_hop.target.as_deref().ok_or_else(|| {
            PlatformError::invalid("service-connect attachment route next hop is missing a target")
        })?;
        if target_identity_id != service_identity.id.as_str() {
            return Err(PlatformError::invalid(format!(
                "service-connect attachment route {} targets service identity {}, not {}",
                private_route.id, target_identity_id, service_identity.id
            )));
        }

        let existing = self
            .list_service_connect_attachments_for_private_network(private_network_id)
            .await?;
        if existing.iter().any(|attachment| {
            attachment.private_route_id == private_route.id
                && attachment.service_identity_id == service_identity.id
        }) {
            return Err(PlatformError::conflict(
                "service-connect attachment already exists for route and service identity",
            ));
        }

        let id = ServiceConnectAttachmentId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate service-connect attachment id")
                .with_detail(error.to_string())
        })?;
        let mut record = ServiceConnectAttachmentRecord {
            id: id.clone(),
            private_network_id: private_network_id.clone(),
            private_route_id: private_route.id.clone(),
            route_table_id: private_route.route_table_id.clone(),
            service_identity_id: service_identity.id.clone(),
            service_identity_subject: service_identity.subject.clone(),
            destination: private_route.destination.clone(),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                service_connect_attachment_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "netsec.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.service_connect_attachments
            .create(
                &private_network_scoped_key(private_network_id, id.as_str()),
                record.clone(),
            )
            .await?;
        let mut details = serde_json::json!({
            "private_network_id": private_network_id,
            "private_route_id": record.private_route_id,
            "route_table_id": record.route_table_id,
            "service_identity_id": record.service_identity_id,
            "service_identity_subject": record.service_identity_subject,
            "destination": record.destination,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "netsec.private_network.service_connect_attachment.created.v1",
            "service_connect_attachment",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_nat_gateway(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreateNatGatewayRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_nat_gateway_authorized(private_network_id, request, context, None)
            .await
    }

    async fn create_nat_gateway_authorized(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreateNatGatewayRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        let _ = self.private_network_by_id(private_network_id).await?;
        let name = normalize_resource_name("name", &request.name)?;
        let tenant_id = effective_tenant_id(request.tenant_id, context)?;
        let cell = normalize_resource_name("cell", &request.cell)?;
        let public_ip = normalize_ipv4(&request.public_ip)?.to_string();
        let subnet_id = request
            .subnet_id
            .as_deref()
            .map(parse_subnet_id)
            .transpose()?;
        if let Some(subnet_id) = subnet_id.as_ref() {
            let _ = self.subnet_by_id(private_network_id, subnet_id).await?;
        }
        let route_table_ids = self
            .route_table_ids_for_private_network(private_network_id, request.route_table_ids)
            .await?;

        let existing_nat_gateways = self
            .list_nat_gateways_for_private_network(private_network_id)
            .await?;
        if existing_nat_gateways
            .iter()
            .any(|gateway| gateway.name.eq_ignore_ascii_case(&name))
        {
            return Err(PlatformError::conflict(
                "nat gateway name already exists in private network",
            ));
        }

        let id = NatGatewayId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate nat gateway id")
                .with_detail(error.to_string())
        })?;
        let mut record = NatGatewayRecord {
            id: id.clone(),
            private_network_id: private_network_id.clone(),
            name,
            tenant_id: tenant_id.clone(),
            cell: cell.clone(),
            public_ip,
            subnet_id,
            route_table_ids,
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(tenant_id.clone()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                nat_gateway_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "netsec.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.nat_gateways
            .create(
                &private_network_scoped_key(private_network_id, id.as_str()),
                record.clone(),
            )
            .await?;
        let mut details = serde_json::json!({
            "private_network_id": private_network_id,
            "tenant_id": tenant_id,
            "cell": cell,
            "subnet_id": record.subnet_id,
            "route_table_ids": record.route_table_ids,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "netsec.private_network.nat_gateway.created.v1",
            "nat_gateway",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_transit_attachment(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreateTransitAttachmentRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_transit_attachment_authorized(private_network_id, request, context, None)
            .await
    }

    async fn create_transit_attachment_authorized(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreateTransitAttachmentRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        let _ = self.private_network_by_id(private_network_id).await?;
        let name = normalize_resource_name("name", &request.name)?;
        let tenant_id = effective_tenant_id(request.tenant_id, context)?;
        let cell = normalize_resource_name("cell", &request.cell)?;
        let transit_private_network_id =
            parse_private_network_id(&request.transit_private_network_id)?;
        if transit_private_network_id == *private_network_id {
            return Err(PlatformError::invalid(
                "transit_private_network_id must reference a different private network",
            ));
        }
        let _ = self
            .private_network_by_id(&transit_private_network_id)
            .await?;
        let transit_tenant_id =
            normalize_resource_name("transit_tenant_id", &request.transit_tenant_id)?;
        let transit_cell = normalize_resource_name("transit_cell", &request.transit_cell)?;
        let route_table_ids = self
            .route_table_ids_for_private_network(private_network_id, request.route_table_ids)
            .await?;

        let existing_transit_attachments = self
            .list_transit_attachments_for_private_network(private_network_id)
            .await?;
        if existing_transit_attachments
            .iter()
            .any(|attachment| attachment.name.eq_ignore_ascii_case(&name))
        {
            return Err(PlatformError::conflict(
                "transit attachment name already exists in private network",
            ));
        }

        let id = TransitAttachmentId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate transit attachment id")
                .with_detail(error.to_string())
        })?;
        let mut record = TransitAttachmentRecord {
            id: id.clone(),
            private_network_id: private_network_id.clone(),
            name,
            tenant_id: tenant_id.clone(),
            cell: cell.clone(),
            transit_private_network_id,
            transit_tenant_id,
            transit_cell,
            route_table_ids,
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(tenant_id.clone()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                transit_attachment_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "netsec.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.transit_attachments
            .create(
                &private_network_scoped_key(private_network_id, id.as_str()),
                record.clone(),
            )
            .await?;
        let mut details = serde_json::json!({
            "private_network_id": private_network_id,
            "tenant_id": tenant_id,
            "cell": cell,
            "transit_private_network_id": record.transit_private_network_id,
            "transit_tenant_id": record.transit_tenant_id,
            "transit_cell": record.transit_cell,
            "route_table_ids": record.route_table_ids,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "netsec.private_network.transit_attachment.created.v1",
            "transit_attachment",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_vpn_connection(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreateVpnConnectionRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_vpn_connection_authorized(private_network_id, request, context, None)
            .await
    }

    async fn create_vpn_connection_authorized(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreateVpnConnectionRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        let _ = self.private_network_by_id(private_network_id).await?;
        let name = normalize_resource_name("name", &request.name)?;
        let tenant_id = effective_tenant_id(request.tenant_id, context)?;
        let cell = normalize_resource_name("cell", &request.cell)?;
        let gateway_address = normalize_ipv4(&request.gateway_address)?.to_string();
        let route_table_ids = self
            .route_table_ids_for_private_network(private_network_id, request.route_table_ids)
            .await?;
        let routing_mode =
            normalize_vpn_routing_mode(request.routing_mode.as_deref().unwrap_or("static"))?;
        let mut remote_cidrs = Vec::with_capacity(request.remote_cidrs.len());
        for raw in request.remote_cidrs {
            let cidr = normalize_cidr_selector(&raw)?;
            if cidr.starts_with("ipset:") {
                return Err(PlatformError::invalid("vpn remote cidrs must be concrete"));
            }
            if !remote_cidrs.contains(&cidr) {
                remote_cidrs.push(cidr);
            }
        }
        if remote_cidrs.is_empty() {
            return Err(PlatformError::invalid("remote_cidrs may not be empty"));
        }

        let existing_vpn_connections = self
            .list_vpn_connections_for_private_network(private_network_id)
            .await?;
        if existing_vpn_connections
            .iter()
            .any(|connection| connection.name.eq_ignore_ascii_case(&name))
        {
            return Err(PlatformError::conflict(
                "vpn connection name already exists in private network",
            ));
        }

        let id = VpnConnectionId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate vpn connection id")
                .with_detail(error.to_string())
        })?;
        let mut record = VpnConnectionRecord {
            id: id.clone(),
            private_network_id: private_network_id.clone(),
            name,
            tenant_id: tenant_id.clone(),
            cell: cell.clone(),
            gateway_address,
            remote_cidrs,
            route_table_ids,
            routing_mode,
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(tenant_id.clone()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                vpn_connection_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "netsec.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.vpn_connections
            .create(
                &private_network_scoped_key(private_network_id, id.as_str()),
                record.clone(),
            )
            .await?;
        let mut details = serde_json::json!({
            "private_network_id": private_network_id,
            "tenant_id": tenant_id,
            "cell": cell,
            "gateway_address": record.gateway_address,
            "remote_cidrs": record.remote_cidrs,
            "route_table_ids": record.route_table_ids,
            "routing_mode": record.routing_mode,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "netsec.private_network.vpn_connection.created.v1",
            "vpn_connection",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_peering_connection(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreatePeeringConnectionRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_peering_connection_authorized(private_network_id, request, context, None)
            .await
    }

    async fn create_peering_connection_authorized(
        &self,
        private_network_id: &PrivateNetworkId,
        request: CreatePeeringConnectionRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        let _ = self.private_network_by_id(private_network_id).await?;
        let name = normalize_resource_name("name", &request.name)?;
        let tenant_id = effective_tenant_id(request.tenant_id, context)?;
        let cell = normalize_resource_name("cell", &request.cell)?;
        let peer_private_network_id = parse_private_network_id(&request.peer_private_network_id)?;
        if peer_private_network_id == *private_network_id {
            return Err(PlatformError::invalid(
                "peer_private_network_id must reference a different private network",
            ));
        }
        let _ = self.private_network_by_id(&peer_private_network_id).await?;
        let peer_tenant_id = normalize_resource_name("peer_tenant_id", &request.peer_tenant_id)?;
        let peer_cell = normalize_resource_name("peer_cell", &request.peer_cell)?;
        let route_table_ids = self
            .route_table_ids_for_private_network(private_network_id, request.route_table_ids)
            .await?;

        let existing_peering_connections = self
            .list_peering_connections_for_private_network(private_network_id)
            .await?;
        if existing_peering_connections
            .iter()
            .any(|peering| peering.name.eq_ignore_ascii_case(&name))
        {
            return Err(PlatformError::conflict(
                "peering connection name already exists in private network",
            ));
        }

        let id = PeeringConnectionId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate peering connection id")
                .with_detail(error.to_string())
        })?;
        let mut record = PeeringConnectionRecord {
            id: id.clone(),
            private_network_id: private_network_id.clone(),
            name,
            tenant_id: tenant_id.clone(),
            cell: cell.clone(),
            peer_private_network_id,
            peer_tenant_id,
            peer_cell,
            route_table_ids,
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(tenant_id.clone()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                peering_connection_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "netsec.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.peering_connections
            .create(
                &private_network_scoped_key(private_network_id, id.as_str()),
                record.clone(),
            )
            .await?;
        let mut details = serde_json::json!({
            "private_network_id": private_network_id,
            "tenant_id": tenant_id,
            "cell": cell,
            "peer_private_network_id": record.peer_private_network_id,
            "peer_tenant_id": record.peer_tenant_id,
            "peer_cell": record.peer_cell,
            "route_table_ids": record.route_table_ids,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "netsec.private_network.peering.created.v1",
            "peering_connection",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_service_identity(
        &self,
        request: CreateServiceIdentityRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_service_identity_authorized(request, context, None)
            .await
    }

    async fn create_service_identity_authorized(
        &self,
        request: CreateServiceIdentityRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        let subject = normalize_service_subject(&request.subject)?;
        if request.mtls_cert_fingerprint.trim().is_empty() {
            return Err(PlatformError::invalid(
                "mtls_cert_fingerprint may not be empty",
            ));
        }

        let existing = self.service_identities.get(&subject).await?;
        if existing.is_some() {
            return Err(PlatformError::conflict(
                "service identity subject already exists",
            ));
        }

        let mut allowed_private_networks =
            Vec::with_capacity(request.allowed_private_networks.len());
        for raw in request.allowed_private_networks {
            let network_id = PrivateNetworkId::parse(raw).map_err(|error| {
                PlatformError::invalid("invalid private network id").with_detail(error.to_string())
            })?;
            let _ = self
                .private_networks
                .get(network_id.as_str())
                .await?
                .ok_or_else(|| {
                    PlatformError::not_found(format!(
                        "private network {} does not exist",
                        network_id
                    ))
                })?;
            allowed_private_networks.push(network_id);
        }
        allowed_private_networks.sort();
        allowed_private_networks.dedup();

        let id = ServiceIdentityId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate service identity id")
                .with_detail(error.to_string())
        })?;
        let mut record = ServiceIdentityRecord {
            id: id.clone(),
            subject: subject.clone(),
            mtls_cert_fingerprint: request.mtls_cert_fingerprint.trim().to_ascii_lowercase(),
            labels: request
                .labels
                .into_iter()
                .map(|(key, value)| {
                    (
                        key.trim().to_ascii_lowercase(),
                        value.trim().to_ascii_lowercase(),
                    )
                })
                .collect(),
            allowed_private_networks,
            enabled: request.enabled.unwrap_or(true),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                service_identity_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "netsec.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.service_identities
            .create(&subject, record.clone())
            .await?;
        let mut details = serde_json::json!({
            "subject": record.subject,
            "enabled": record.enabled,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "netsec.service_identity.created.v1",
            "service_identity",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_egress_rule(
        &self,
        request: CreateEgressRuleRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_egress_rule_authorized(request, context, None)
            .await
    }

    async fn create_egress_rule_authorized(
        &self,
        request: CreateEgressRuleRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        let target_kind = normalize_target_kind(&request.target_kind)?;
        let action = normalize_action(&request.action)?;
        let target_value = if target_kind == "cidr" {
            normalize_cidr_selector(&request.target_value)?
        } else {
            request.target_value.trim().to_ascii_lowercase()
        };

        if request.reason.trim().is_empty() {
            return Err(PlatformError::invalid("reason may not be empty"));
        }

        let id = EgressRuleId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate egress rule id")
                .with_detail(error.to_string())
        })?;
        let mut record = EgressRuleRecord {
            id: id.clone(),
            target_kind,
            target_value,
            action,
            reason: request.reason,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                egress_rule_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "netsec.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.egress_rules
            .create(id.as_str(), record.clone())
            .await?;
        let mut details = serde_json::json!({
            "target_kind": record.target_kind,
            "action": record.action,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "netsec.egress_rule.created.v1",
            "egress_rule",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_inspection_profile(
        &self,
        request: CreateInspectionProfileRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_inspection_profile_authorized(request, context, None)
            .await
    }

    async fn create_inspection_profile_authorized(
        &self,
        request: CreateInspectionProfileRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        if request.name.trim().is_empty() {
            return Err(PlatformError::invalid("name may not be empty"));
        }
        let blocked_countries = request
            .blocked_countries
            .into_iter()
            .map(|value| normalize_country_code(&value))
            .collect::<Result<Vec<_>>>()?;
        let ddos_mode = normalize_ddos_mode(request.ddos_mode.as_deref().unwrap_or("monitor"))?;
        let id = PolicyId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate inspection profile id")
                .with_detail(error.to_string())
        })?;
        let mut profile = InspectionProfileRecord {
            id: id.clone(),
            name: request.name.trim().to_owned(),
            blocked_countries,
            min_waf_score: request.min_waf_score.unwrap_or(0).min(1000),
            max_bot_score: request.max_bot_score.unwrap_or(1000).min(1000),
            ddos_mode,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                inspection_profile_mutation_digest(&profile, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut profile.metadata, "netsec.mutation_digest");
            profile.change_authorization = Some(authorization.clone());
        }
        self.inspection_profiles
            .create(id.as_str(), profile.clone())
            .await?;
        let mut details = serde_json::json!({
            "blocked_countries": profile.blocked_countries,
            "min_waf_score": profile.min_waf_score,
            "max_bot_score": profile.max_bot_score,
            "ddos_mode": profile.ddos_mode,
        });
        if let Some(authorization) = profile.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "netsec.inspection_profile.created.v1",
            "inspection_profile",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &profile)
    }

    async fn evaluate_inspection_profile(
        &self,
        request: &PolicyVerifyRequest,
    ) -> Result<(Option<PolicyId>, Option<String>, Option<String>)> {
        let Some(profile_id) = request.inspection_profile_id.as_deref() else {
            return Ok((None, None, None));
        };
        let inspection_id = PolicyId::parse(profile_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid inspection_profile_id").with_detail(error.to_string())
        })?;
        let profile = self
            .inspection_profiles
            .get(inspection_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("inspection profile does not exist"))?
            .value;
        let source_country = request
            .source_country
            .as_deref()
            .map(normalize_country_code)
            .transpose()?;

        if let Some(country) = source_country.as_deref()
            && profile
                .blocked_countries
                .iter()
                .any(|entry| entry.eq_ignore_ascii_case(country))
        {
            return Ok((
                Some(inspection_id),
                Some(format!("blocked by geo restriction for country {country}")),
                source_country,
            ));
        }
        if let Some(waf_score) = request.waf_score
            && waf_score < profile.min_waf_score
        {
            return Ok((
                Some(inspection_id),
                Some(format!(
                    "blocked by waf threshold {} < {}",
                    waf_score, profile.min_waf_score
                )),
                source_country,
            ));
        }
        if let Some(bot_score) = request.bot_score
            && bot_score > profile.max_bot_score
        {
            return Ok((
                Some(inspection_id),
                Some(format!(
                    "blocked by bot score {} > {}",
                    bot_score, profile.max_bot_score
                )),
                source_country,
            ));
        }
        if request.ddos_suspected.unwrap_or(false) {
            match profile.ddos_mode.as_str() {
                "block" => {
                    return Ok((
                        Some(inspection_id),
                        Some(String::from("blocked by ddos_mode=block")),
                        source_country,
                    ));
                }
                "mitigate" => {
                    return Ok((
                        Some(inspection_id),
                        Some(String::from("blocked for ddos mitigation")),
                        source_country,
                    ));
                }
                _ => {}
            }
        }
        Ok((
            Some(inspection_id),
            Some(String::from("inspection profile passed")),
            source_country,
        ))
    }

    async fn verify_policy(
        &self,
        request: PolicyVerifyRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let destination = normalize_ipv4(&request.destination)?;
        let protocol = normalize_protocol(&request.protocol)?;
        let source_identity = request
            .source_identity
            .as_deref()
            .map(normalize_service_subject)
            .transpose()?;
        let source_identity_record = if let Some(subject) = source_identity.as_deref() {
            self.service_identities
                .get(subject)
                .await?
                .map(|stored| stored.value)
        } else {
            None
        };
        let (inspection_profile_id, inspection_result, source_country) =
            self.evaluate_inspection_profile(&request).await?;
        let inspection_denial = inspection_result.as_deref().and_then(|reason| {
            if reason.starts_with("blocked ") {
                Some(reason.to_owned())
            } else {
                None
            }
        });
        let quarantine_denial = self
            .abuse_quarantine_denial(
                source_identity.as_deref(),
                destination,
                &request.destination,
            )
            .await?;
        let egress_result = self
            .evaluate_egress_rules(destination, &request.destination)
            .await?;

        let mut selected_policy: Option<NetPolicyId> = None;
        let (mut verdict, mut reason) = if let Some(reason) = inspection_denial {
            (String::from("deny"), reason)
        } else if let Some(reason) = quarantine_denial {
            (String::from("deny"), reason)
        } else {
            match egress_result {
                EgressDecision::Allow => (
                    String::from("allow"),
                    String::from("egress allowlist matched"),
                ),
                EgressDecision::Deny(reason) => (String::from("deny"), reason),
                EgressDecision::NoRules => (
                    String::from("deny"),
                    String::from("deny-by-default (no egress rules)"),
                ),
            }
        };

        if verdict == "allow" && source_identity.is_some() && source_identity_record.is_none() {
            verdict = String::from("deny");
            reason = String::from("source identity is not registered");
        }

        if verdict == "allow"
            && source_identity_record
                .as_ref()
                .is_some_and(|record| !record.enabled)
        {
            verdict = String::from("deny");
            reason = String::from("source identity is disabled");
        }

        if verdict == "allow"
            && let Some(deny_reason) = self
                .private_network_identity_denial(destination, source_identity_record.as_ref())
                .await?
        {
            verdict = String::from("deny");
            reason = deny_reason;
        }

        if verdict == "allow" {
            let policies = self
                .policies
                .list()
                .await?
                .into_iter()
                .filter(|(_, record)| !record.deleted)
                .map(|(_, record)| record.value)
                .collect::<Vec<_>>();
            let selected_policy_record = policies
                .iter()
                .filter(|policy| selector_matches(&policy.selector, &request.labels))
                .min_by(|left, right| {
                    left.metadata
                        .created_at
                        .cmp(&right.metadata.created_at)
                        .then_with(|| left.id.cmp(&right.id))
                });

            if let Some(policy) = selected_policy_record {
                selected_policy = Some(policy.id.clone());

                if policy.mtls_mode == "strict" {
                    if let Some(identity) = source_identity_record.as_ref() {
                        if identity.mtls_cert_fingerprint.trim().is_empty() {
                            verdict = String::from("deny");
                            reason =
                                String::from("mTLS strict policy requires certificate fingerprint");
                        }
                    } else {
                        verdict = String::from("deny");
                        reason = String::from("mTLS strict policy requires source identity");
                    }
                }

                if verdict == "allow"
                    && source_identity.is_some()
                    && source_identity_record.is_none()
                {
                    verdict = String::from("deny");
                    reason = String::from("source identity is not registered");
                }

                if verdict == "allow" {
                    let mut ip_set_index = BTreeMap::new();
                    if policy_uses_ipset_targets(policy) {
                        let ip_sets = self
                            .ip_sets
                            .list()
                            .await?
                            .into_iter()
                            .filter(|(_, record)| !record.deleted)
                            .map(|(_, record)| record.value)
                            .collect::<Vec<_>>();
                        for ip_set in ip_sets {
                            ip_set_index.insert(ip_set.id.to_string(), ip_set);
                        }
                    }

                    verdict = String::from("deny");
                    reason = String::from("deny-by-default (no matching policy)");

                    let mut matched_rule = false;
                    for rule in &policy.rules {
                        if rule.direction != "egress" {
                            continue;
                        }
                        if rule.protocol != "any" && rule.protocol != protocol {
                            continue;
                        }
                        if request.port < rule.port_start || request.port > rule.port_end {
                            continue;
                        }
                        if rule.require_identity && source_identity_record.is_none() {
                            continue;
                        }
                        if !cidr_selector_matches(&rule.cidr, destination, &ip_set_index)? {
                            continue;
                        }

                        matched_rule = true;
                        verdict = rule.action.clone();
                        reason = format!("matched policy rule priority {}", rule.priority);
                        break;
                    }

                    if !matched_rule {
                        verdict = policy.default_action.clone();
                        reason = String::from("applied policy default action");
                    }
                }
            } else {
                verdict = String::from("deny");
                reason = String::from("deny-by-default (no matching policy)");
            }
        }

        let flow_id = FlowAuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate flow audit id")
                .with_detail(error.to_string())
        })?;
        let audit = FlowAuditRecord {
            id: flow_id.clone(),
            source_identity,
            destination: request.destination,
            protocol,
            port: request.port,
            verdict: verdict.clone(),
            policy_id: selected_policy.clone(),
            inspection_profile_id: inspection_profile_id.clone(),
            inspection_reason: inspection_result.clone(),
            source_country,
            waf_score: request.waf_score,
            bot_score: request.bot_score,
            ddos_suspected: request.ddos_suspected.unwrap_or(false),
            reason: reason.clone(),
            observed_at: OffsetDateTime::now_utc(),
        };
        self.flow_audit
            .create(flow_id.as_str(), audit.clone())
            .await?;
        self.append_event(
            "netsec.policy.evaluated.v1",
            "flow_audit",
            flow_id.as_str(),
            "evaluated",
            serde_json::json!({
                "verdict": verdict,
                "reason": reason,
                "destination": audit.destination,
            }),
            context,
        )
        .await?;

        json_response(
            StatusCode::OK,
            &PolicyVerifyResponse {
                verdict: audit.verdict,
                reason: audit.reason,
                policy_id: audit.policy_id.map(|id| id.to_string()),
                flow_audit_id: flow_id.to_string(),
            },
        )
    }

    async fn list_flow_audit(&self, query: &FlowAuditQuery) -> Result<Response<ApiBody>> {
        let mut values = self
            .flow_audit
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .filter(|record| flow_audit_matches(record, query))
            .collect::<Vec<_>>();
        values.sort_by(|left, right| right.observed_at.cmp(&left.observed_at));
        if let Some(limit) = query.limit {
            values.truncate(limit);
        }
        json_response(StatusCode::OK, &values)
    }

    async fn summarize_flow_audit(&self, query: &FlowAuditQuery) -> Result<Response<ApiBody>> {
        let mut values = self
            .flow_audit
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .filter(|record| flow_audit_matches(record, query))
            .collect::<Vec<_>>();
        values.sort_by(|left, right| right.observed_at.cmp(&left.observed_at));
        if let Some(limit) = query.limit {
            values.truncate(limit);
        }

        let mut allow = 0_usize;
        let mut deny = 0_usize;
        let mut by_reason = BTreeMap::new();
        let mut by_destination = BTreeMap::new();
        let mut by_identity = BTreeMap::new();

        for record in &values {
            match record.verdict.as_str() {
                "allow" => allow += 1,
                "deny" => deny += 1,
                _ => {}
            }
            increment_counter(&mut by_reason, &record.reason);
            increment_counter(&mut by_destination, &record.destination);
            if let Some(identity) = &record.source_identity {
                increment_counter(&mut by_identity, identity);
            }
        }

        let summary = FlowAuditSummaryResponse {
            total: values.len(),
            allow,
            deny,
            top_reasons: top_counters(&by_reason, 10),
            top_destinations: top_counters(&by_destination, 10),
            top_source_identities: top_counters(&by_identity, 10),
        };
        json_response(StatusCode::OK, &summary)
    }

    async fn summary_report(&self) -> Result<Response<ApiBody>> {
        let policies = self
            .policies
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        let mut policy_default_actions = BTreeMap::new();
        let mut policy_mtls_modes = BTreeMap::new();
        let mut rule_actions = BTreeMap::new();
        let mut total_rules = 0_usize;
        for policy in &policies {
            increment_counter(&mut policy_default_actions, &policy.default_action);
            increment_counter(&mut policy_mtls_modes, &policy.mtls_mode);
            for rule in &policy.rules {
                increment_counter(&mut rule_actions, &rule.action);
                total_rules = total_rules.saturating_add(1);
            }
        }

        let ip_sets = self
            .ip_sets
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        let total_cidrs = ip_sets
            .iter()
            .map(|record| record.cidrs.len())
            .sum::<usize>();

        let flow_audit = self
            .flow_audit
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        let mut flow_allow = 0_usize;
        let mut flow_deny = 0_usize;
        let mut flow_severity = BTreeMap::new();
        for record in &flow_audit {
            match record.verdict.as_str() {
                "allow" => flow_allow = flow_allow.saturating_add(1),
                "deny" => flow_deny = flow_deny.saturating_add(1),
                _ => {}
            }
            increment_counter(&mut flow_severity, flow_audit_severity(record));
        }

        let summary = NetsecSummaryResponse {
            policies: NetsecPolicySummary {
                total: policies.len(),
                total_rules,
                default_actions: top_counters(
                    &policy_default_actions,
                    policy_default_actions.len(),
                ),
                mtls_modes: top_counters(&policy_mtls_modes, policy_mtls_modes.len()),
                rule_actions: top_counters(&rule_actions, rule_actions.len()),
            },
            ip_sets: NetsecIpSetSummary {
                total: ip_sets.len(),
                total_cidrs,
            },
            flow_audit: NetsecFlowAuditSummary {
                total: flow_audit.len(),
                allow: flow_allow,
                deny: flow_deny,
                severity: top_counters(&flow_severity, flow_severity.len()),
            },
        };
        json_response(StatusCode::OK, &summary)
    }

    async fn evaluate_egress_rules(
        &self,
        destination: Ipv4Addr,
        destination_raw: &str,
    ) -> Result<EgressDecision> {
        let rules = self
            .egress_rules
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        if rules.is_empty() {
            return Ok(EgressDecision::NoRules);
        }

        for rule in rules {
            let matched = if rule.target_kind == "cidr" {
                cidr_selector_matches(&rule.target_value, destination, &BTreeMap::new())?
            } else {
                destination_raw.eq_ignore_ascii_case(&rule.target_value)
            };
            if matched {
                if rule.action == "allow" {
                    return Ok(EgressDecision::Allow);
                }
                return Ok(EgressDecision::Deny(format!(
                    "blocked by egress rule {}: {}",
                    rule.id, rule.reason
                )));
            }
        }

        Ok(EgressDecision::Deny(String::from(
            "deny-by-default (egress rules configured but none matched)",
        )))
    }

    async fn abuse_quarantine_denial(
        &self,
        source_identity: Option<&str>,
        destination: Ipv4Addr,
        destination_raw: &str,
    ) -> Result<Option<String>> {
        let now = OffsetDateTime::now_utc();
        let destination_string = destination.to_string();
        let quarantines = self
            .abuse_quarantines
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        for quarantine in quarantines {
            if quarantine.state != "active" || !quarantine.deny_network {
                continue;
            }
            if quarantine
                .expires_at
                .is_some_and(|expires_at| expires_at <= now)
            {
                continue;
            }
            match quarantine.subject_kind.as_str() {
                "service_identity" => {
                    if source_identity.is_some_and(|subject| subject == quarantine.subject) {
                        return Ok(Some(format!(
                            "blocked by abuse quarantine for {}",
                            quarantine.subject
                        )));
                    }
                }
                "ip_address" => {
                    if quarantine.subject == destination_string
                        || quarantine.subject.eq_ignore_ascii_case(destination_raw)
                    {
                        return Ok(Some(format!(
                            "destination denied by abuse quarantine {}",
                            quarantine.subject
                        )));
                    }
                }
                "hostname" => {
                    if quarantine.subject.eq_ignore_ascii_case(destination_raw) {
                        return Ok(Some(format!(
                            "hostname denied by abuse quarantine {}",
                            quarantine.subject
                        )));
                    }
                }
                _ => {}
            }
        }
        Ok(None)
    }

    async fn private_network_identity_denial(
        &self,
        destination: Ipv4Addr,
        source_identity: Option<&ServiceIdentityRecord>,
    ) -> Result<Option<String>> {
        let destination_raw = destination.to_string();
        let private_networks = self
            .private_networks
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();

        for private_network in private_networks {
            if !evaluate_ipv4_cidr_match(&destination_raw, &private_network.cidr)? {
                continue;
            }
            let Some(identity) = source_identity else {
                return Ok(Some(String::from(
                    "destination belongs to a private network and requires source identity",
                )));
            };
            let explicitly_attached =
                private_network_allows_service_identity(&private_network, identity);
            let service_connected = self
                .private_network_has_service_connect_attachment(
                    &private_network.id,
                    &destination_raw,
                    identity,
                )
                .await?;
            if !explicitly_attached && !service_connected {
                return Ok(Some(format!(
                    "source identity {} is not attached to private network {}",
                    identity.subject, private_network.id
                )));
            }
        }

        Ok(None)
    }

    async fn private_network_has_service_connect_attachment(
        &self,
        private_network_id: &PrivateNetworkId,
        destination: &str,
        identity: &ServiceIdentityRecord,
    ) -> Result<bool> {
        for (_, stored) in self.service_connect_attachments.list().await? {
            if stored.deleted {
                continue;
            }
            let attachment = stored.value;
            if attachment.private_network_id != *private_network_id
                || attachment.service_identity_id != identity.id
            {
                continue;
            }
            if evaluate_ipv4_cidr_match(destination, &attachment.destination)? {
                return Ok(true);
            }
        }
        Ok(false)
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

    async fn optional_change_authorization(
        &self,
        context: &RequestContext,
        change_request_id: Option<&str>,
        mutation_digest: Option<String>,
    ) -> Result<Option<GovernanceChangeAuthorization>> {
        let Some(change_request_id) = change_request_id else {
            return Ok(None);
        };
        let Some(mutation_digest) = mutation_digest else {
            return Ok(None);
        };
        let change_request_id = self.validate_governance_gate(change_request_id).await?;
        Ok(Some(GovernanceChangeAuthorization {
            change_request_id,
            mutation_digest,
            authorized_at: OffsetDateTime::now_utc(),
            provenance: Self::request_governance_provenance(context),
        }))
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
                source_service: String::from("netsec"),
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
            .enqueue("netsec.events.v1", event, Some(&idempotency))
            .await?;
        Ok(())
    }
}

impl HttpService for NetsecService {
    fn name(&self) -> &'static str {
        "netsec"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/netsec")];
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
            let governance_change_request_id =
                extract_change_request_id(request.headers()).map(str::to_owned);
            let segments = path_segments(&path);

            match (method, segments.as_slice()) {
                (Method::GET, ["netsec"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                        "default_posture": "deny_by_default",
                    }),
                )
                .map(Some),
                (Method::GET, ["netsec", "policies"]) => {
                    let values = self
                        .policies
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["netsec", "policies"]) => {
                    let body: CreatePolicyRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_policy_authorized(body, &context, Some(change_request_id))
                            .await
                            .map(Some),
                        None => self.create_policy(body, &context).await.map(Some),
                    }
                }
                (Method::GET, ["netsec", "ipsets"]) => {
                    let values = self
                        .ip_sets
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["netsec", "ipsets"]) => {
                    let body: CreateIpSetRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_ip_set_authorized(body, &context, Some(change_request_id))
                            .await
                            .map(Some),
                        None => self.create_ip_set(body, &context).await.map(Some),
                    }
                }
                (Method::GET, ["netsec", "private-networks"]) => {
                    let values = self
                        .private_networks
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["netsec", "private-networks"]) => {
                    let body: CreatePrivateNetworkRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_private_network_authorized(
                                body,
                                &context,
                                Some(change_request_id),
                            )
                            .await
                            .map(Some),
                        None => self.create_private_network(body, &context).await.map(Some),
                    }
                }
                (Method::GET, ["netsec", "private-networks", private_network_id, "subnets"]) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let values = self
                        .list_subnets_for_private_network(&private_network_id)
                        .await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["netsec", "private-networks", private_network_id, "subnets"]) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let body: CreateSubnetRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_subnet_authorized(
                                &private_network_id,
                                body,
                                &context,
                                Some(change_request_id),
                            )
                            .await
                            .map(Some),
                        None => self
                            .create_subnet(&private_network_id, body, &context)
                            .await
                            .map(Some),
                    }
                }
                (
                    Method::GET,
                    [
                        "netsec",
                        "private-networks",
                        private_network_id,
                        "route-tables",
                    ],
                ) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let values = self
                        .list_route_tables_for_private_network(&private_network_id)
                        .await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (
                    Method::POST,
                    [
                        "netsec",
                        "private-networks",
                        private_network_id,
                        "route-tables",
                    ],
                ) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let body: CreateRouteTableRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_route_table_authorized(
                                &private_network_id,
                                body,
                                &context,
                                Some(change_request_id),
                            )
                            .await
                            .map(Some),
                        None => self
                            .create_route_table(&private_network_id, body, &context)
                            .await
                            .map(Some),
                    }
                }
                (
                    Method::GET,
                    [
                        "netsec",
                        "private-networks",
                        private_network_id,
                        "next-hops",
                    ],
                ) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let values = self
                        .list_next_hops_for_private_network(&private_network_id)
                        .await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (
                    Method::POST,
                    [
                        "netsec",
                        "private-networks",
                        private_network_id,
                        "next-hops",
                    ],
                ) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let body: CreateNextHopRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_next_hop_authorized(
                                &private_network_id,
                                body,
                                &context,
                                Some(change_request_id),
                            )
                            .await
                            .map(Some),
                        None => self
                            .create_next_hop(&private_network_id, body, &context)
                            .await
                            .map(Some),
                    }
                }
                (
                    Method::GET,
                    [
                        "netsec",
                        "private-networks",
                        private_network_id,
                        "route-tables",
                        route_table_id,
                        "routes",
                    ],
                ) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let route_table_id = parse_route_table_id(route_table_id)?;
                    let values = self
                        .list_routes_for_route_table(&private_network_id, &route_table_id)
                        .await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (
                    Method::POST,
                    [
                        "netsec",
                        "private-networks",
                        private_network_id,
                        "route-tables",
                        route_table_id,
                        "routes",
                    ],
                ) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let route_table_id = parse_route_table_id(route_table_id)?;
                    let body: CreatePrivateRouteRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_private_route_authorized(
                                &private_network_id,
                                &route_table_id,
                                body,
                                &context,
                                Some(change_request_id),
                            )
                            .await
                            .map(Some),
                        None => self
                            .create_private_route(
                                &private_network_id,
                                &route_table_id,
                                body,
                                &context,
                            )
                            .await
                            .map(Some),
                    }
                }
                (
                    Method::GET,
                    [
                        "netsec",
                        "private-networks",
                        private_network_id,
                        "service-connect-attachments",
                    ],
                ) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let values = self
                        .list_service_connect_attachments_for_private_network(&private_network_id)
                        .await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (
                    Method::POST,
                    [
                        "netsec",
                        "private-networks",
                        private_network_id,
                        "service-connect-attachments",
                    ],
                ) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let body: CreateServiceConnectAttachmentRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_service_connect_attachment_authorized(
                                &private_network_id,
                                body,
                                &context,
                                Some(change_request_id),
                            )
                            .await
                            .map(Some),
                        None => self
                            .create_service_connect_attachment(&private_network_id, body, &context)
                            .await
                            .map(Some),
                    }
                }
                (
                    Method::GET,
                    [
                        "netsec",
                        "private-networks",
                        private_network_id,
                        "nat-gateways",
                    ],
                ) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let values = self
                        .list_nat_gateways_for_private_network(&private_network_id)
                        .await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (
                    Method::POST,
                    [
                        "netsec",
                        "private-networks",
                        private_network_id,
                        "nat-gateways",
                    ],
                ) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let body: CreateNatGatewayRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_nat_gateway_authorized(
                                &private_network_id,
                                body,
                                &context,
                                Some(change_request_id),
                            )
                            .await
                            .map(Some),
                        None => self
                            .create_nat_gateway(&private_network_id, body, &context)
                            .await
                            .map(Some),
                    }
                }
                (
                    Method::GET,
                    [
                        "netsec",
                        "private-networks",
                        private_network_id,
                        "transit-attachments",
                    ],
                ) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let values = self
                        .list_transit_attachments_for_private_network(&private_network_id)
                        .await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (
                    Method::POST,
                    [
                        "netsec",
                        "private-networks",
                        private_network_id,
                        "transit-attachments",
                    ],
                ) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let body: CreateTransitAttachmentRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_transit_attachment_authorized(
                                &private_network_id,
                                body,
                                &context,
                                Some(change_request_id),
                            )
                            .await
                            .map(Some),
                        None => self
                            .create_transit_attachment(&private_network_id, body, &context)
                            .await
                            .map(Some),
                    }
                }
                (
                    Method::GET,
                    [
                        "netsec",
                        "private-networks",
                        private_network_id,
                        "vpn-connections",
                    ],
                ) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let values = self
                        .list_vpn_connections_for_private_network(&private_network_id)
                        .await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (
                    Method::POST,
                    [
                        "netsec",
                        "private-networks",
                        private_network_id,
                        "vpn-connections",
                    ],
                ) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let body: CreateVpnConnectionRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_vpn_connection_authorized(
                                &private_network_id,
                                body,
                                &context,
                                Some(change_request_id),
                            )
                            .await
                            .map(Some),
                        None => self
                            .create_vpn_connection(&private_network_id, body, &context)
                            .await
                            .map(Some),
                    }
                }
                (Method::GET, ["netsec", "private-networks", private_network_id, "peerings"]) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let values = self
                        .list_peering_connections_for_private_network(&private_network_id)
                        .await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["netsec", "private-networks", private_network_id, "peerings"]) => {
                    let private_network_id = parse_private_network_id(private_network_id)?;
                    let body: CreatePeeringConnectionRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_peering_connection_authorized(
                                &private_network_id,
                                body,
                                &context,
                                Some(change_request_id),
                            )
                            .await
                            .map(Some),
                        None => self
                            .create_peering_connection(&private_network_id, body, &context)
                            .await
                            .map(Some),
                    }
                }
                (Method::GET, ["netsec", "service-identities"]) => {
                    let values = self
                        .service_identities
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["netsec", "service-identities"]) => {
                    let body: CreateServiceIdentityRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_service_identity_authorized(
                                body,
                                &context,
                                Some(change_request_id),
                            )
                            .await
                            .map(Some),
                        None => self.create_service_identity(body, &context).await.map(Some),
                    }
                }
                (Method::GET, ["netsec", "egress-rules"]) => {
                    let values = self
                        .egress_rules
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["netsec", "egress-rules"]) => {
                    let body: CreateEgressRuleRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_egress_rule_authorized(body, &context, Some(change_request_id))
                            .await
                            .map(Some),
                        None => self.create_egress_rule(body, &context).await.map(Some),
                    }
                }
                (Method::GET, ["netsec", "inspection-profiles"]) => {
                    let values = self
                        .inspection_profiles
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["netsec", "inspection-profiles"]) => {
                    let body: CreateInspectionProfileRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_inspection_profile_authorized(
                                body,
                                &context,
                                Some(change_request_id),
                            )
                            .await
                            .map(Some),
                        None => self
                            .create_inspection_profile(body, &context)
                            .await
                            .map(Some),
                    }
                }
                (Method::GET, ["netsec", "summary"]) => self.summary_report().await.map(Some),
                (Method::GET, ["netsec", "flow-audit"]) => {
                    let query = parse_flow_audit_query(&query)?;
                    self.list_flow_audit(&query).await.map(Some)
                }
                (Method::GET, ["netsec", "flow-audit", "summary"]) => {
                    let query = parse_flow_audit_query(&query)?;
                    self.summarize_flow_audit(&query).await.map(Some)
                }
                (Method::POST, ["netsec", "policy-verify"]) => {
                    let body: PolicyVerifyRequest = parse_json(request).await?;
                    self.verify_policy(body, &context).await.map(Some)
                }
                (Method::GET, ["netsec", "outbox"]) => {
                    let messages = self.outbox.list_all().await?;
                    json_response(StatusCode::OK, &messages).map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn extract_change_request_id(headers: &http::HeaderMap) -> Option<&str> {
    headers
        .get(GOVERNANCE_CHANGE_REQUEST_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
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

fn policy_mutation_digest(
    policy: &NetsecPolicy,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "name": policy.name,
        "selector": policy.selector,
        "default_action": policy.default_action,
        "mtls_mode": policy.mtls_mode,
        "rules": policy.rules,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode netsec policy mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn private_network_mutation_digest(
    record: &PrivateNetworkRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "name": record.name,
        "cidr": record.cidr,
        "attachments": record.attachments,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode private-network mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn ip_set_mutation_digest(
    record: &IpSetRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "name": record.name,
        "cidrs": record.cidrs,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode ip-set mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn subnet_mutation_digest(
    record: &SubnetRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "private_network_id": record.private_network_id,
        "name": record.name,
        "cidr": record.cidr,
        "route_table_id": record.route_table_id,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode subnet mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn route_table_mutation_digest(
    record: &RouteTableRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "private_network_id": record.private_network_id,
        "name": record.name,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode route-table mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn next_hop_mutation_digest(
    record: &NextHopRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "private_network_id": record.private_network_id,
        "name": record.name,
        "kind": record.kind,
        "target": record.target,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode next-hop mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn private_route_mutation_digest(
    record: &PrivateRouteRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "private_network_id": record.private_network_id,
        "route_table_id": record.route_table_id,
        "destination": record.destination,
        "next_hop_id": record.next_hop_id,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode private-route mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn service_connect_attachment_mutation_digest(
    record: &ServiceConnectAttachmentRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "private_network_id": record.private_network_id,
        "private_route_id": record.private_route_id,
        "route_table_id": record.route_table_id,
        "service_identity_id": record.service_identity_id,
        "service_identity_subject": record.service_identity_subject,
        "destination": record.destination,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode service-connect mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn nat_gateway_mutation_digest(
    record: &NatGatewayRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "private_network_id": record.private_network_id,
        "name": record.name,
        "tenant_id": record.tenant_id,
        "cell": record.cell,
        "public_ip": record.public_ip,
        "subnet_id": record.subnet_id,
        "route_table_ids": record.route_table_ids,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode nat-gateway mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn transit_attachment_mutation_digest(
    record: &TransitAttachmentRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "private_network_id": record.private_network_id,
        "name": record.name,
        "tenant_id": record.tenant_id,
        "cell": record.cell,
        "transit_private_network_id": record.transit_private_network_id,
        "transit_tenant_id": record.transit_tenant_id,
        "transit_cell": record.transit_cell,
        "route_table_ids": record.route_table_ids,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode transit-attachment mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn vpn_connection_mutation_digest(
    record: &VpnConnectionRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "private_network_id": record.private_network_id,
        "name": record.name,
        "tenant_id": record.tenant_id,
        "cell": record.cell,
        "gateway_address": record.gateway_address,
        "remote_cidrs": record.remote_cidrs,
        "route_table_ids": record.route_table_ids,
        "routing_mode": record.routing_mode,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode vpn-connection mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn peering_connection_mutation_digest(
    record: &PeeringConnectionRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "private_network_id": record.private_network_id,
        "name": record.name,
        "tenant_id": record.tenant_id,
        "cell": record.cell,
        "peer_private_network_id": record.peer_private_network_id,
        "peer_tenant_id": record.peer_tenant_id,
        "peer_cell": record.peer_cell,
        "route_table_ids": record.route_table_ids,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode peering mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn service_identity_mutation_digest(
    record: &ServiceIdentityRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "subject": record.subject,
        "mtls_cert_fingerprint": record.mtls_cert_fingerprint,
        "labels": record.labels,
        "allowed_private_networks": record.allowed_private_networks,
        "enabled": record.enabled,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode service-identity mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn egress_rule_mutation_digest(
    record: &EgressRuleRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "target_kind": record.target_kind,
        "target_value": record.target_value,
        "action": record.action,
        "reason": record.reason,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode egress-rule mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn inspection_profile_mutation_digest(
    profile: &InspectionProfileRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "name": profile.name,
        "blocked_countries": profile.blocked_countries,
        "min_waf_score": profile.min_waf_score,
        "max_bot_score": profile.max_bot_score,
        "ddos_mode": profile.ddos_mode,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode inspection-profile mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EgressDecision {
    Allow,
    Deny(String),
    NoRules,
}

fn selector_matches(
    selector: &BTreeMap<String, String>,
    labels: &BTreeMap<String, String>,
) -> bool {
    selector
        .iter()
        .all(|(key, value)| labels.get(key) == Some(value))
}

fn parse_flow_audit_query(raw: &BTreeMap<String, String>) -> Result<FlowAuditQuery> {
    let verdict = raw
        .get("verdict")
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    if let Some(value) = &verdict
        && value != "allow"
        && value != "deny"
    {
        return Err(PlatformError::invalid("verdict must be `allow` or `deny`"));
    }

    let limit = raw
        .get("limit")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|error| {
                    PlatformError::invalid("invalid flow audit limit")
                        .with_detail(error.to_string())
                })
                .and_then(|parsed| {
                    if parsed == 0 {
                        Err(PlatformError::invalid("flow audit limit must be > 0"))
                    } else {
                        Ok(parsed.min(10_000))
                    }
                })
        })
        .transpose()?;

    let since = raw
        .get("since")
        .map(|value| {
            OffsetDateTime::parse(value, &Rfc3339).map_err(|error| {
                PlatformError::invalid("invalid `since`; expected RFC3339 timestamp")
                    .with_detail(error.to_string())
            })
        })
        .transpose()?;
    let until = raw
        .get("until")
        .map(|value| {
            OffsetDateTime::parse(value, &Rfc3339).map_err(|error| {
                PlatformError::invalid("invalid `until`; expected RFC3339 timestamp")
                    .with_detail(error.to_string())
            })
        })
        .transpose()?;
    if let (Some(since), Some(until)) = (since, until)
        && since > until
    {
        return Err(PlatformError::invalid("`since` may not be after `until`"));
    }

    Ok(FlowAuditQuery {
        verdict,
        source_identity: raw
            .get("source_identity")
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty()),
        destination: raw
            .get("destination")
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()),
        protocol: raw
            .get("protocol")
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty()),
        policy_id: raw
            .get("policy_id")
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()),
        inspection_profile_id: raw
            .get("inspection_profile_id")
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()),
        since,
        until,
        limit,
    })
}

fn flow_audit_matches(record: &FlowAuditRecord, query: &FlowAuditQuery) -> bool {
    if let Some(verdict) = &query.verdict
        && !record.verdict.eq_ignore_ascii_case(verdict)
    {
        return false;
    }
    if let Some(identity) = &query.source_identity {
        let Some(source_identity) = &record.source_identity else {
            return false;
        };
        if !source_identity.eq_ignore_ascii_case(identity) {
            return false;
        }
    }
    if let Some(destination) = &query.destination
        && record.destination != *destination
    {
        return false;
    }
    if let Some(protocol) = &query.protocol
        && !record.protocol.eq_ignore_ascii_case(protocol)
    {
        return false;
    }
    if let Some(policy_id) = &query.policy_id
        && record.policy_id.as_ref().map(|value| value.as_str()) != Some(policy_id.as_str())
    {
        return false;
    }
    if let Some(inspection_profile_id) = &query.inspection_profile_id
        && record
            .inspection_profile_id
            .as_ref()
            .map(|value| value.as_str())
            != Some(inspection_profile_id.as_str())
    {
        return false;
    }
    if let Some(since) = query.since
        && record.observed_at < since
    {
        return false;
    }
    if let Some(until) = query.until
        && record.observed_at > until
    {
        return false;
    }
    true
}

fn increment_counter(counters: &mut BTreeMap<String, usize>, key: &str) {
    let entry = counters.entry(key.to_owned()).or_insert(0);
    *entry += 1;
}

fn top_counters(counters: &BTreeMap<String, usize>, limit: usize) -> Vec<FlowAuditSummaryCounter> {
    let mut values = counters
        .iter()
        .map(|(key, count)| FlowAuditSummaryCounter {
            key: key.clone(),
            count: *count,
        })
        .collect::<Vec<_>>();
    values.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.key.cmp(&right.key))
    });
    values.truncate(limit);
    values
}

fn flow_audit_severity(record: &FlowAuditRecord) -> &'static str {
    if record.ddos_suspected {
        return "critical";
    }
    if record.verdict == "deny" {
        if record.inspection_reason.is_some()
            || record.waf_score.is_some()
            || record.bot_score.is_some()
            || record.source_country.is_some()
        {
            return "high";
        }
        return "medium";
    }
    "low"
}

fn policy_uses_ipset_targets(policy: &NetsecPolicy) -> bool {
    policy
        .rules
        .iter()
        .any(|rule| rule.cidr.starts_with("ipset:"))
}

fn private_network_allows_service_identity(
    private_network: &PrivateNetworkRecord,
    identity: &ServiceIdentityRecord,
) -> bool {
    let attached = private_network.attachments.iter().any(|entry| {
        let normalized = entry.trim().to_ascii_lowercase();
        normalized == identity.subject || normalized == identity.id.as_str().to_ascii_lowercase()
    });
    let explicitly_allowed = identity
        .allowed_private_networks
        .iter()
        .any(|network_id| network_id == &private_network.id);
    attached || explicitly_allowed
}

fn normalize_resource_name(field_name: &str, value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(format!(
            "{field_name} may not be empty"
        )));
    }
    Ok(normalized.to_owned())
}

fn normalize_next_hop_kind(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "local" | "service_identity" | "ip_address" | "blackhole" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "next hop kind must be one of local/service_identity/ip_address/blackhole",
        )),
    }
}

fn parse_private_network_id(value: &str) -> Result<PrivateNetworkId> {
    PrivateNetworkId::parse(value.trim().to_owned()).map_err(|error| {
        PlatformError::invalid("invalid private_network_id").with_detail(error.to_string())
    })
}

fn parse_route_table_id(value: &str) -> Result<RouteTableId> {
    RouteTableId::parse(value.trim().to_owned()).map_err(|error| {
        PlatformError::invalid("invalid route_table_id").with_detail(error.to_string())
    })
}

fn parse_subnet_id(value: &str) -> Result<SubnetId> {
    SubnetId::parse(value.trim().to_owned())
        .map_err(|error| PlatformError::invalid("invalid subnet_id").with_detail(error.to_string()))
}

fn parse_next_hop_id(value: &str) -> Result<NextHopId> {
    NextHopId::parse(value.trim().to_owned()).map_err(|error| {
        PlatformError::invalid("invalid next_hop_id").with_detail(error.to_string())
    })
}

fn parse_private_route_id(value: &str) -> Result<PrivateRouteId> {
    PrivateRouteId::parse(value.trim().to_owned()).map_err(|error| {
        PlatformError::invalid("invalid private_route_id").with_detail(error.to_string())
    })
}

fn private_network_scoped_key(private_network_id: &PrivateNetworkId, record_id: &str) -> String {
    format!("{}:{record_id}", private_network_id.as_str())
}

fn private_route_scoped_key(
    private_network_id: &PrivateNetworkId,
    route_table_id: &RouteTableId,
    route_id: &str,
) -> String {
    format!(
        "{}:{}:{route_id}",
        private_network_id.as_str(),
        route_table_id.as_str()
    )
}

fn normalize_optional_scope_value(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn effective_tenant_id(
    request_tenant_id: Option<String>,
    context: &RequestContext,
) -> Result<String> {
    let request_tenant_id = normalize_optional_scope_value(request_tenant_id);
    let context_tenant_id = normalize_optional_scope_value(context.tenant_id.clone());
    if let (Some(request_tenant_id), Some(context_tenant_id)) =
        (&request_tenant_id, &context_tenant_id)
        && request_tenant_id != context_tenant_id
    {
        return Err(PlatformError::forbidden(
            "tenant_id must match request tenant scope",
        ));
    }
    request_tenant_id
        .or(context_tenant_id)
        .ok_or_else(|| PlatformError::invalid("tenant_id may not be empty"))
}

fn normalize_vpn_routing_mode(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "static" | "bgp" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "routing_mode must be one of static/bgp",
        )),
    }
}

fn normalize_service_subject(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    let Some(subject) = normalized.strip_prefix("svc:") else {
        return Err(PlatformError::invalid(
            "service identity subject must start with `svc:`",
        ));
    };
    if subject.is_empty() {
        return Err(PlatformError::invalid(
            "service identity subject must include a name after `svc:`",
        ));
    }
    if !subject.chars().all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '-' | '_' | '.')
    }) {
        return Err(PlatformError::invalid(
            "service identity subject contains unsupported characters",
        ));
    }
    Ok(normalized)
}

fn normalize_attachment_reference(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("attachment entry may not be empty"));
    }
    if ServiceIdentityId::parse(normalized.clone()).is_ok() {
        return Ok(normalized);
    }
    if normalized.starts_with("svc:") {
        return normalize_service_subject(&normalized);
    }
    Err(PlatformError::invalid(
        "attachment entries must be `svc:<name>` or `sid_<id>`",
    ))
}

fn normalize_action(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "allow" | "deny" => Ok(normalized),
        _ => Err(PlatformError::invalid("action must be `allow` or `deny`")),
    }
}

fn normalize_direction(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "ingress" | "egress" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "direction must be `ingress` or `egress`",
        )),
    }
}

fn normalize_protocol(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "tcp" | "udp" | "http" | "https" | "any" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "protocol must be one of tcp/udp/http/https/any",
        )),
    }
}

fn normalize_mtls_mode(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "strict" | "permissive" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "mtls_mode must be `strict` or `permissive`",
        )),
    }
}

fn normalize_target_kind(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "cidr" | "hostname" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "target_kind must be `cidr` or `hostname`",
        )),
    }
}

fn normalize_country_code(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_uppercase();
    if normalized.len() == 2
        && normalized
            .chars()
            .all(|character| character.is_ascii_alphabetic())
    {
        Ok(normalized)
    } else {
        Err(PlatformError::invalid(
            "country code must be a two-letter ISO-3166 value",
        ))
    }
}

fn normalize_ddos_mode(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "monitor" | "mitigate" | "block" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "ddos_mode must be one of monitor/mitigate/block",
        )),
    }
}

fn normalize_cidr_selector(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if let Some(rest) = normalized.strip_prefix("ipset:") {
        let _ = IpSetId::parse(rest.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid ipset reference").with_detail(error.to_string())
        })?;
        return Ok(normalized);
    }
    parse_ipv4_cidr(&normalized)?;
    Ok(normalized)
}

fn normalize_ipv4(value: &str) -> Result<Ipv4Addr> {
    Ipv4Addr::from_str(value.trim()).map_err(|error| {
        PlatformError::invalid("destination must be a valid IPv4 address")
            .with_detail(error.to_string())
    })
}

fn default_true() -> bool {
    true
}

fn cidr_selector_matches(
    selector: &str,
    ip: Ipv4Addr,
    ip_sets: &BTreeMap<String, IpSetRecord>,
) -> Result<bool> {
    if let Some(reference) = selector.strip_prefix("ipset:") {
        let Some(ip_set) = ip_sets.get(reference) else {
            return Ok(false);
        };
        for cidr in &ip_set.cidrs {
            if ipv4_in_cidr(ip, cidr)? {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    ipv4_in_cidr(ip, selector)
}

fn ipv4_in_cidr(ip: Ipv4Addr, cidr: &str) -> Result<bool> {
    let (network, prefix) = parse_ipv4_cidr(cidr)?;
    let ip_u32 = u32::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32_u8.saturating_sub(prefix))
    };
    Ok((ip_u32 & mask) == (network & mask))
}

fn parse_ipv4_cidr(value: &str) -> Result<(u32, u8)> {
    let Some((raw_ip, raw_prefix)) = value.split_once('/') else {
        return Err(PlatformError::invalid(
            "cidr must include `/` prefix length",
        ));
    };
    let prefix = raw_prefix.parse::<u8>().map_err(|error| {
        PlatformError::invalid("cidr prefix must be an integer").with_detail(error.to_string())
    })?;
    if prefix > 32 {
        return Err(PlatformError::invalid("cidr prefix must be <= 32"));
    }
    let ip = Ipv4Addr::from_str(raw_ip).map_err(|error| {
        PlatformError::invalid("cidr network must be a valid IPv4 address")
            .with_detail(error.to_string())
    })?;
    Ok((u32::from(ip), prefix))
}

fn ipv4_cidr_bounds(cidr: &str) -> Result<(u32, u32)> {
    let (network, prefix) = parse_ipv4_cidr(cidr)?;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32_u8.saturating_sub(prefix))
    };
    let start = network & mask;
    Ok((start, start | !mask))
}

fn cidr_contains_cidr(parent: &str, child: &str) -> Result<bool> {
    let (parent_start, parent_end) = ipv4_cidr_bounds(parent)?;
    let (child_start, child_end) = ipv4_cidr_bounds(child)?;
    Ok(parent_start <= child_start && child_end <= parent_end)
}

fn cidr_ranges_overlap(left: &str, right: &str) -> Result<bool> {
    let (left_start, left_end) = ipv4_cidr_bounds(left)?;
    let (right_start, right_end) = ipv4_cidr_bounds(right)?;
    Ok(left_start <= right_end && right_start <= left_end)
}

/// Public helper for benchmark and integration checks on CIDR matching.
pub fn evaluate_ipv4_cidr_match(ip: &str, cidr: &str) -> Result<bool> {
    let ip = normalize_ipv4(ip)?;
    ipv4_in_cidr(ip, cidr)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    use http_body_util::BodyExt;
    use proptest::prelude::*;
    use serde_json::Value;
    use tempfile::tempdir;
    use time::{Duration, OffsetDateTime};

    use super::{
        AbuseQuarantineHookRecord, CreateEgressRuleRequest, CreateInspectionProfileRequest,
        CreateIpSetRequest, CreateNatGatewayRequest, CreateNextHopRequest,
        CreatePeeringConnectionRequest, CreatePolicyRequest, CreatePrivateNetworkRequest,
        CreatePrivateRouteRequest, CreateRouteTableRequest, CreateServiceConnectAttachmentRequest,
        CreateServiceIdentityRequest, CreateSubnetRequest, CreateTransitAttachmentRequest,
        CreateVpnConnectionRequest, GovernanceChangeRequestMirror, IpSetRecord, NatGatewayRecord,
        NetPolicyId, NetsecPolicy, NetsecRule, NextHopRecord, PeeringConnectionRecord,
        PolicyVerifyRequest, PrivateNetworkRecord, PrivateRouteRecord, RouteTableRecord,
        ServiceConnectAttachmentRecord, ServiceIdentityRecord, SubnetRecord,
        TransitAttachmentRecord, VpnConnectionRecord, parse_flow_audit_query,
    };
    use crate::NetsecService;
    use uhost_api::ApiBody;
    use uhost_core::{RequestContext, sha256_hex};
    use uhost_types::{
        ChangeRequestId, FlowAuditId, GovernanceChangeAuthorization, IpSetId, OwnershipScope,
        ResourceLifecycleState, ResourceMetadata,
    };

    async fn read_json<T: serde::de::DeserializeOwned>(response: http::Response<ApiBody>) -> T {
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
    }

    async fn seed_governance_change_request(service: &NetsecService, state: &str) -> String {
        let change_request_id =
            ChangeRequestId::generate().unwrap_or_else(|error| panic!("{error}"));
        service
            .governance_change_requests
            .create(
                change_request_id.as_str(),
                GovernanceChangeRequestMirror {
                    id: change_request_id.clone(),
                    state: String::from(state),
                    extra: std::collections::BTreeMap::new(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        change_request_id.to_string()
    }

    fn assert_governed_netsec_metadata(
        authorization: Option<&GovernanceChangeAuthorization>,
        metadata: &ResourceMetadata,
        change_request_id: &str,
    ) {
        let authorization =
            authorization.unwrap_or_else(|| panic!("missing governance change authorization"));
        assert_eq!(authorization.change_request_id.as_str(), change_request_id);
        assert_eq!(authorization.mutation_digest.len(), 64);
        assert_eq!(
            metadata
                .annotations
                .get("governance.change_request_id")
                .map(String::as_str),
            Some(change_request_id)
        );
        assert_eq!(
            metadata
                .annotations
                .get("netsec.mutation_digest")
                .map(String::len),
            Some(64)
        );
    }

    #[tokio::test]
    async fn create_policy_persists_change_authorization_when_governed() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("netsec.operator");
        let change_request_id = seed_governance_change_request(&service, "approved").await;

        let policy: NetsecPolicy = read_json(
            service
                .create_policy_authorized(
                    CreatePolicyRequest {
                        name: String::from("governed-policy"),
                        selector: BTreeMap::new(),
                        default_action: Some(String::from("deny")),
                        mtls_mode: Some(String::from("strict")),
                        rules: vec![NetsecRule {
                            priority: 10,
                            action: String::from("allow"),
                            direction: String::from("egress"),
                            protocol: String::from("tcp"),
                            cidr: String::from("10.0.0.0/8"),
                            port_start: 443,
                            port_end: 443,
                            require_identity: false,
                        }],
                    },
                    &context,
                    Some(change_request_id.as_str()),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let authorization = policy
            .change_authorization
            .as_ref()
            .unwrap_or_else(|| panic!("missing netsec policy change authorization"));
        assert_eq!(
            authorization.change_request_id.as_str(),
            change_request_id.as_str()
        );
        assert_eq!(authorization.mutation_digest.len(), 64);
        assert_eq!(
            policy
                .metadata
                .annotations
                .get("governance.change_request_id")
                .map(String::as_str),
            Some(change_request_id.as_str())
        );
        assert_eq!(
            policy
                .metadata
                .annotations
                .get("netsec.mutation_digest")
                .map(String::len),
            Some(64)
        );
    }

    #[tokio::test]
    async fn remaining_governed_create_surfaces_persist_change_authorization() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("netsec.operator")
            .with_tenant("tenant-alpha");
        let change_request_id = seed_governance_change_request(&service, "approved").await;

        let private_network: PrivateNetworkRecord = read_json(
            service
                .create_private_network_authorized(
                    CreatePrivateNetworkRequest {
                        name: String::from("network-a"),
                        cidr: String::from("10.90.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                    Some(change_request_id.as_str()),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let transit_network: PrivateNetworkRecord = read_json(
            service
                .create_private_network(
                    CreatePrivateNetworkRequest {
                        name: String::from("transit-hub"),
                        cidr: String::from("10.91.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let peer_network: PrivateNetworkRecord = read_json(
            service
                .create_private_network(
                    CreatePrivateNetworkRequest {
                        name: String::from("peer-network"),
                        cidr: String::from("10.92.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let ip_set: IpSetRecord = read_json(
            service
                .create_ip_set_authorized(
                    CreateIpSetRequest {
                        name: String::from("internal"),
                        cidrs: vec![String::from("10.0.0.0/8"), String::from("192.168.0.0/16")],
                    },
                    &context,
                    Some(change_request_id.as_str()),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_governed_netsec_metadata(
            ip_set.change_authorization.as_ref(),
            &ip_set.metadata,
            &change_request_id,
        );

        let route_table: RouteTableRecord = read_json(
            service
                .create_route_table_authorized(
                    &private_network.id,
                    CreateRouteTableRequest {
                        name: String::from("main"),
                    },
                    &context,
                    Some(change_request_id.as_str()),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_governed_netsec_metadata(
            route_table.change_authorization.as_ref(),
            &route_table.metadata,
            &change_request_id,
        );

        let subnet: SubnetRecord = read_json(
            service
                .create_subnet_authorized(
                    &private_network.id,
                    CreateSubnetRequest {
                        name: String::from("app-a"),
                        cidr: String::from("10.90.1.0/24"),
                        route_table_id: Some(route_table.id.to_string()),
                    },
                    &context,
                    Some(change_request_id.as_str()),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_governed_netsec_metadata(
            subnet.change_authorization.as_ref(),
            &subnet.metadata,
            &change_request_id,
        );

        let service_identity: ServiceIdentityRecord = read_json(
            service
                .create_service_identity_authorized(
                    CreateServiceIdentityRequest {
                        subject: String::from("svc:payments"),
                        mtls_cert_fingerprint: String::from("AA:BB:CC"),
                        labels: BTreeMap::from([(String::from("tier"), String::from("edge"))]),
                        allowed_private_networks: vec![private_network.id.to_string()],
                        enabled: Some(true),
                    },
                    &context,
                    Some(change_request_id.as_str()),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_governed_netsec_metadata(
            service_identity.change_authorization.as_ref(),
            &service_identity.metadata,
            &change_request_id,
        );

        let next_hop: NextHopRecord = read_json(
            service
                .create_next_hop_authorized(
                    &private_network.id,
                    CreateNextHopRequest {
                        name: String::from("payments-hop"),
                        kind: String::from("service_identity"),
                        target: Some(service_identity.id.to_string()),
                    },
                    &context,
                    Some(change_request_id.as_str()),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_governed_netsec_metadata(
            next_hop.change_authorization.as_ref(),
            &next_hop.metadata,
            &change_request_id,
        );

        let private_route: PrivateRouteRecord = read_json(
            service
                .create_private_route_authorized(
                    &private_network.id,
                    &route_table.id,
                    CreatePrivateRouteRequest {
                        destination: String::from("10.90.2.0/24"),
                        next_hop_id: next_hop.id.to_string(),
                    },
                    &context,
                    Some(change_request_id.as_str()),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_governed_netsec_metadata(
            private_route.change_authorization.as_ref(),
            &private_route.metadata,
            &change_request_id,
        );

        let attachment: ServiceConnectAttachmentRecord = read_json(
            service
                .create_service_connect_attachment_authorized(
                    &private_network.id,
                    CreateServiceConnectAttachmentRequest {
                        service_identity: service_identity.subject.clone(),
                        private_route_id: private_route.id.to_string(),
                    },
                    &context,
                    Some(change_request_id.as_str()),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_governed_netsec_metadata(
            attachment.change_authorization.as_ref(),
            &attachment.metadata,
            &change_request_id,
        );

        let nat_gateway: NatGatewayRecord = read_json(
            service
                .create_nat_gateway_authorized(
                    &private_network.id,
                    CreateNatGatewayRequest {
                        name: String::from("nat-a"),
                        tenant_id: None,
                        cell: String::from("use1-cell-a"),
                        public_ip: String::from("203.0.113.10"),
                        subnet_id: Some(subnet.id.to_string()),
                        route_table_ids: vec![route_table.id.to_string()],
                    },
                    &context,
                    Some(change_request_id.as_str()),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_governed_netsec_metadata(
            nat_gateway.change_authorization.as_ref(),
            &nat_gateway.metadata,
            &change_request_id,
        );

        let transit_attachment: TransitAttachmentRecord = read_json(
            service
                .create_transit_attachment_authorized(
                    &private_network.id,
                    CreateTransitAttachmentRequest {
                        name: String::from("hub-link"),
                        tenant_id: None,
                        cell: String::from("use1-cell-a"),
                        transit_private_network_id: transit_network.id.to_string(),
                        transit_tenant_id: String::from("tenant-shared"),
                        transit_cell: String::from("use1-transit-b"),
                        route_table_ids: vec![route_table.id.to_string()],
                    },
                    &context,
                    Some(change_request_id.as_str()),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_governed_netsec_metadata(
            transit_attachment.change_authorization.as_ref(),
            &transit_attachment.metadata,
            &change_request_id,
        );

        let vpn_connection: VpnConnectionRecord = read_json(
            service
                .create_vpn_connection_authorized(
                    &private_network.id,
                    CreateVpnConnectionRequest {
                        name: String::from("branch-link"),
                        tenant_id: None,
                        cell: String::from("use1-cell-a"),
                        gateway_address: String::from("198.51.100.7"),
                        remote_cidrs: vec![
                            String::from("172.16.0.0/16"),
                            String::from("192.168.50.0/24"),
                        ],
                        route_table_ids: vec![route_table.id.to_string()],
                        routing_mode: Some(String::from("bgp")),
                    },
                    &context,
                    Some(change_request_id.as_str()),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_governed_netsec_metadata(
            vpn_connection.change_authorization.as_ref(),
            &vpn_connection.metadata,
            &change_request_id,
        );

        let peering_connection: PeeringConnectionRecord = read_json(
            service
                .create_peering_connection_authorized(
                    &private_network.id,
                    CreatePeeringConnectionRequest {
                        name: String::from("peer-link"),
                        tenant_id: None,
                        cell: String::from("use1-cell-a"),
                        peer_private_network_id: peer_network.id.to_string(),
                        peer_tenant_id: String::from("tenant-beta"),
                        peer_cell: String::from("usw2-cell-b"),
                        route_table_ids: vec![route_table.id.to_string()],
                    },
                    &context,
                    Some(change_request_id.as_str()),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_governed_netsec_metadata(
            peering_connection.change_authorization.as_ref(),
            &peering_connection.metadata,
            &change_request_id,
        );
    }

    #[tokio::test]
    async fn verify_defaults_to_deny_without_egress_rules() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: Some(String::from("svc:api")),
                    destination: String::from("10.10.10.2"),
                    protocol: String::from("tcp"),
                    port: 443,
                    labels: BTreeMap::new(),
                    inspection_profile_id: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::OK);
        let audits = service
            .flow_audit
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].1.value.verdict, "deny");
    }

    #[tokio::test]
    async fn verify_allows_when_egress_and_policy_match() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_egress_rule(
                CreateEgressRuleRequest {
                    target_kind: String::from("cidr"),
                    target_value: String::from("10.0.0.0/8"),
                    action: String::from("allow"),
                    reason: String::from("allow private network"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut selector = BTreeMap::new();
        selector.insert(String::from("tier"), String::from("backend"));
        let _ = service
            .create_policy(
                CreatePolicyRequest {
                    name: String::from("backend-egress"),
                    selector,
                    default_action: Some(String::from("deny")),
                    mtls_mode: Some(String::from("strict")),
                    rules: vec![NetsecRule {
                        priority: 1,
                        action: String::from("allow"),
                        direction: String::from("egress"),
                        protocol: String::from("tcp"),
                        cidr: String::from("10.0.0.0/8"),
                        port_start: 443,
                        port_end: 443,
                        require_identity: true,
                    }],
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_service_identity(
                CreateServiceIdentityRequest {
                    subject: String::from("svc:backend"),
                    mtls_cert_fingerprint: String::from("sha256:backend-cert"),
                    labels: BTreeMap::new(),
                    allowed_private_networks: Vec::new(),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut labels = BTreeMap::new();
        labels.insert(String::from("tier"), String::from("backend"));

        let response = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: Some(String::from("svc:backend")),
                    destination: String::from("10.1.2.3"),
                    protocol: String::from("tcp"),
                    port: 443,
                    labels,
                    inspection_profile_id: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::OK);
        let audits = service
            .flow_audit
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].1.value.verdict, "allow");
    }

    #[tokio::test]
    async fn verify_denies_unregistered_identity_for_strict_mtls() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_egress_rule(
                CreateEgressRuleRequest {
                    target_kind: String::from("cidr"),
                    target_value: String::from("10.0.0.0/8"),
                    action: String::from("allow"),
                    reason: String::from("allow private network"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut selector = BTreeMap::new();
        selector.insert(String::from("tier"), String::from("backend"));
        let _ = service
            .create_policy(
                CreatePolicyRequest {
                    name: String::from("strict-egress"),
                    selector,
                    default_action: Some(String::from("deny")),
                    mtls_mode: Some(String::from("strict")),
                    rules: vec![NetsecRule {
                        priority: 1,
                        action: String::from("allow"),
                        direction: String::from("egress"),
                        protocol: String::from("tcp"),
                        cidr: String::from("10.0.0.0/8"),
                        port_start: 443,
                        port_end: 443,
                        require_identity: true,
                    }],
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut labels = BTreeMap::new();
        labels.insert(String::from("tier"), String::from("backend"));
        let _ = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: Some(String::from("svc:missing")),
                    destination: String::from("10.1.2.3"),
                    protocol: String::from("tcp"),
                    port: 443,
                    labels,
                    inspection_profile_id: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let audits = service
            .flow_audit
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].1.value.verdict, "deny");
        assert!(
            audits[0]
                .1
                .value
                .reason
                .contains("source identity is not registered")
        );
    }

    #[tokio::test]
    async fn private_network_attachment_is_enforced() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_egress_rule(
                CreateEgressRuleRequest {
                    target_kind: String::from("cidr"),
                    target_value: String::from("10.0.0.0/8"),
                    action: String::from("allow"),
                    reason: String::from("allow private network"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_private_network(
                CreatePrivateNetworkRequest {
                    name: String::from("internal"),
                    cidr: String::from("10.0.0.0/8"),
                    attachments: vec![String::from("svc:payments")],
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let private_networks = service
            .private_networks
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let private_network_id = private_networks[0].1.value.id.to_string();

        let mut selector = BTreeMap::new();
        selector.insert(String::from("tier"), String::from("backend"));
        let _ = service
            .create_policy(
                CreatePolicyRequest {
                    name: String::from("private-routing"),
                    selector,
                    default_action: Some(String::from("deny")),
                    mtls_mode: Some(String::from("strict")),
                    rules: vec![NetsecRule {
                        priority: 1,
                        action: String::from("allow"),
                        direction: String::from("egress"),
                        protocol: String::from("tcp"),
                        cidr: String::from("10.0.0.0/8"),
                        port_start: 443,
                        port_end: 443,
                        require_identity: true,
                    }],
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_service_identity(
                CreateServiceIdentityRequest {
                    subject: String::from("svc:api"),
                    mtls_cert_fingerprint: String::from("sha256:api-cert"),
                    labels: BTreeMap::new(),
                    allowed_private_networks: Vec::new(),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_service_identity(
                CreateServiceIdentityRequest {
                    subject: String::from("svc:router"),
                    mtls_cert_fingerprint: String::from("sha256:router-cert"),
                    labels: BTreeMap::new(),
                    allowed_private_networks: vec![private_network_id],
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut labels = BTreeMap::new();
        labels.insert(String::from("tier"), String::from("backend"));
        let _ = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: Some(String::from("svc:api")),
                    destination: String::from("10.1.2.3"),
                    protocol: String::from("tcp"),
                    port: 443,
                    labels: labels.clone(),
                    inspection_profile_id: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: Some(String::from("svc:router")),
                    destination: String::from("10.1.2.3"),
                    protocol: String::from("tcp"),
                    port: 443,
                    labels,
                    inspection_profile_id: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let audits = service
            .flow_audit
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(audits.len(), 2);
        let verdicts = audits
            .into_iter()
            .map(|(_, stored)| stored.value.verdict)
            .collect::<Vec<_>>();
        assert!(verdicts.iter().any(|value| value == "deny"));
        assert!(verdicts.iter().any(|value| value == "allow"));
    }

    #[tokio::test]
    async fn service_connect_attachment_authorizes_east_west_flow() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_egress_rule(
                CreateEgressRuleRequest {
                    target_kind: String::from("cidr"),
                    target_value: String::from("10.90.0.0/16"),
                    action: String::from("allow"),
                    reason: String::from("allow attached private route"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut selector = BTreeMap::new();
        selector.insert(String::from("tier"), String::from("backend"));
        let _ = service
            .create_policy(
                CreatePolicyRequest {
                    name: String::from("service-connect"),
                    selector,
                    default_action: Some(String::from("deny")),
                    mtls_mode: Some(String::from("strict")),
                    rules: vec![NetsecRule {
                        priority: 1,
                        action: String::from("allow"),
                        direction: String::from("egress"),
                        protocol: String::from("tcp"),
                        cidr: String::from("10.90.0.0/16"),
                        port_start: 443,
                        port_end: 443,
                        require_identity: true,
                    }],
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let private_network: PrivateNetworkRecord = read_json(
            service
                .create_private_network(
                    CreatePrivateNetworkRequest {
                        name: String::from("payments"),
                        cidr: String::from("10.90.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let _service_identity: ServiceIdentityRecord = read_json(
            service
                .create_service_identity(
                    CreateServiceIdentityRequest {
                        subject: String::from("svc:payments"),
                        mtls_cert_fingerprint: String::from("sha256:payments-cert"),
                        labels: BTreeMap::new(),
                        allowed_private_networks: Vec::new(),
                        enabled: Some(true),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let route_table: RouteTableRecord = read_json(
            service
                .create_route_table(
                    &private_network.id,
                    CreateRouteTableRequest {
                        name: String::from("main"),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let next_hop: NextHopRecord = read_json(
            service
                .create_next_hop(
                    &private_network.id,
                    CreateNextHopRequest {
                        name: String::from("payments-svc"),
                        kind: String::from("service_identity"),
                        target: Some(String::from("svc:payments")),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let private_route: PrivateRouteRecord = read_json(
            service
                .create_private_route(
                    &private_network.id,
                    &route_table.id,
                    CreatePrivateRouteRequest {
                        destination: String::from("10.90.10.0/24"),
                        next_hop_id: next_hop.id.to_string(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let mut labels = BTreeMap::new();
        labels.insert(String::from("tier"), String::from("backend"));
        let _ = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: Some(String::from("svc:payments")),
                    destination: String::from("10.90.10.42"),
                    protocol: String::from("tcp"),
                    port: 443,
                    labels: labels.clone(),
                    inspection_profile_id: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let attachment: ServiceConnectAttachmentRecord = read_json(
            service
                .create_service_connect_attachment(
                    &private_network.id,
                    CreateServiceConnectAttachmentRequest {
                        service_identity: String::from("svc:payments"),
                        private_route_id: private_route.id.to_string(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let _ = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: Some(String::from("svc:payments")),
                    destination: String::from("10.90.10.42"),
                    protocol: String::from("tcp"),
                    port: 443,
                    labels,
                    inspection_profile_id: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(attachment.private_network_id, private_network.id);
        assert_eq!(attachment.private_route_id, private_route.id);
        assert_eq!(attachment.route_table_id, route_table.id);
        assert_eq!(attachment.service_identity_subject, "svc:payments");
        assert_eq!(attachment.destination, "10.90.10.0/24");

        let attachments = service
            .list_service_connect_attachments_for_private_network(&private_network.id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(attachments.len(), 1);

        let audits = service
            .flow_audit
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(audits.len(), 2);
        let deny_reason = audits
            .iter()
            .find(|(_, stored)| stored.value.verdict == "deny")
            .map(|(_, stored)| stored.value.reason.clone())
            .unwrap_or_else(|| panic!("expected one deny audit"));
        assert!(deny_reason.contains("not attached to private network"));
        assert!(
            audits
                .iter()
                .any(|(_, stored)| stored.value.verdict == "allow")
        );
    }

    #[tokio::test]
    async fn service_connect_attachment_rejects_route_identity_mismatch() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let private_network: PrivateNetworkRecord = read_json(
            service
                .create_private_network(
                    CreatePrivateNetworkRequest {
                        name: String::from("mismatch"),
                        cidr: String::from("10.91.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let _ = service
            .create_service_identity(
                CreateServiceIdentityRequest {
                    subject: String::from("svc:orders"),
                    mtls_cert_fingerprint: String::from("sha256:orders-cert"),
                    labels: BTreeMap::new(),
                    allowed_private_networks: Vec::new(),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_service_identity(
                CreateServiceIdentityRequest {
                    subject: String::from("svc:payments"),
                    mtls_cert_fingerprint: String::from("sha256:payments-cert"),
                    labels: BTreeMap::new(),
                    allowed_private_networks: Vec::new(),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let route_table: RouteTableRecord = read_json(
            service
                .create_route_table(
                    &private_network.id,
                    CreateRouteTableRequest {
                        name: String::from("main"),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let next_hop: NextHopRecord = read_json(
            service
                .create_next_hop(
                    &private_network.id,
                    CreateNextHopRequest {
                        name: String::from("orders-svc"),
                        kind: String::from("service_identity"),
                        target: Some(String::from("svc:orders")),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let private_route: PrivateRouteRecord = read_json(
            service
                .create_private_route(
                    &private_network.id,
                    &route_table.id,
                    CreatePrivateRouteRequest {
                        destination: String::from("10.91.20.0/24"),
                        next_hop_id: next_hop.id.to_string(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let error = service
            .create_service_connect_attachment(
                &private_network.id,
                CreateServiceConnectAttachmentRequest {
                    service_identity: String::from("svc:payments"),
                    private_route_id: private_route.id.to_string(),
                },
                &context,
            )
            .await
            .expect_err("mismatched route target should be rejected");
        assert!(error.message.contains("targets service identity"));
    }

    #[tokio::test]
    async fn service_connect_attachment_rejects_non_service_identity_route() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let private_network: PrivateNetworkRecord = read_json(
            service
                .create_private_network(
                    CreatePrivateNetworkRequest {
                        name: String::from("non-service-route"),
                        cidr: String::from("10.92.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let _ = service
            .create_service_identity(
                CreateServiceIdentityRequest {
                    subject: String::from("svc:payments"),
                    mtls_cert_fingerprint: String::from("sha256:payments-cert"),
                    labels: BTreeMap::new(),
                    allowed_private_networks: Vec::new(),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let route_table: RouteTableRecord = read_json(
            service
                .create_route_table(
                    &private_network.id,
                    CreateRouteTableRequest {
                        name: String::from("main"),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let next_hop: NextHopRecord = read_json(
            service
                .create_next_hop(
                    &private_network.id,
                    CreateNextHopRequest {
                        name: String::from("local-target"),
                        kind: String::from("local"),
                        target: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let private_route: PrivateRouteRecord = read_json(
            service
                .create_private_route(
                    &private_network.id,
                    &route_table.id,
                    CreatePrivateRouteRequest {
                        destination: String::from("10.92.20.0/24"),
                        next_hop_id: next_hop.id.to_string(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let error = service
            .create_service_connect_attachment(
                &private_network.id,
                CreateServiceConnectAttachmentRequest {
                    service_identity: String::from("svc:payments"),
                    private_route_id: private_route.id.to_string(),
                },
                &context,
            )
            .await
            .expect_err("non-service next hop should be rejected");
        assert!(
            error
                .message
                .contains("must target a `service_identity` next hop")
        );
    }

    #[tokio::test]
    async fn service_connect_attachment_rejects_duplicate_route_identity_pair() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let private_network: PrivateNetworkRecord = read_json(
            service
                .create_private_network(
                    CreatePrivateNetworkRequest {
                        name: String::from("duplicate"),
                        cidr: String::from("10.93.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let _ = service
            .create_service_identity(
                CreateServiceIdentityRequest {
                    subject: String::from("svc:orders"),
                    mtls_cert_fingerprint: String::from("sha256:orders-cert"),
                    labels: BTreeMap::new(),
                    allowed_private_networks: Vec::new(),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let route_table: RouteTableRecord = read_json(
            service
                .create_route_table(
                    &private_network.id,
                    CreateRouteTableRequest {
                        name: String::from("main"),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let next_hop: NextHopRecord = read_json(
            service
                .create_next_hop(
                    &private_network.id,
                    CreateNextHopRequest {
                        name: String::from("orders-svc"),
                        kind: String::from("service_identity"),
                        target: Some(String::from("svc:orders")),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let private_route: PrivateRouteRecord = read_json(
            service
                .create_private_route(
                    &private_network.id,
                    &route_table.id,
                    CreatePrivateRouteRequest {
                        destination: String::from("10.93.20.0/24"),
                        next_hop_id: next_hop.id.to_string(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let _attachment: ServiceConnectAttachmentRecord = read_json(
            service
                .create_service_connect_attachment(
                    &private_network.id,
                    CreateServiceConnectAttachmentRequest {
                        service_identity: String::from("svc:orders"),
                        private_route_id: private_route.id.to_string(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let error = service
            .create_service_connect_attachment(
                &private_network.id,
                CreateServiceConnectAttachmentRequest {
                    service_identity: String::from("svc:orders"),
                    private_route_id: private_route.id.to_string(),
                },
                &context,
            )
            .await
            .expect_err("duplicate service-connect attachment should be rejected");
        assert!(
            error
                .message
                .contains("already exists for route and service identity")
        );
    }

    #[tokio::test]
    async fn private_network_routing_resources_are_scoped_and_persisted() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let private_network: PrivateNetworkRecord = read_json(
            service
                .create_private_network(
                    CreatePrivateNetworkRequest {
                        name: String::from("routing"),
                        cidr: String::from("10.60.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let service_identity: ServiceIdentityRecord = read_json(
            service
                .create_service_identity(
                    CreateServiceIdentityRequest {
                        subject: String::from("svc:router"),
                        mtls_cert_fingerprint: String::from("sha256:router-cert"),
                        labels: BTreeMap::new(),
                        allowed_private_networks: vec![private_network.id.to_string()],
                        enabled: Some(true),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let route_table: RouteTableRecord = read_json(
            service
                .create_route_table(
                    &private_network.id,
                    CreateRouteTableRequest {
                        name: String::from("main"),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let subnet: SubnetRecord = read_json(
            service
                .create_subnet(
                    &private_network.id,
                    CreateSubnetRequest {
                        name: String::from("app-a"),
                        cidr: String::from("10.60.1.0/24"),
                        route_table_id: Some(route_table.id.to_string()),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let next_hop: NextHopRecord = read_json(
            service
                .create_next_hop(
                    &private_network.id,
                    CreateNextHopRequest {
                        name: String::from("router-hop"),
                        kind: String::from("service_identity"),
                        target: Some(String::from("svc:router")),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let route: PrivateRouteRecord = read_json(
            service
                .create_private_route(
                    &private_network.id,
                    &route_table.id,
                    CreatePrivateRouteRequest {
                        destination: String::from("0.0.0.0/0"),
                        next_hop_id: next_hop.id.to_string(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        assert_eq!(subnet.private_network_id, private_network.id);
        assert_eq!(subnet.route_table_id.as_ref(), Some(&route_table.id));
        assert_eq!(next_hop.private_network_id, private_network.id);
        assert_eq!(
            next_hop.target.as_deref(),
            Some(service_identity.id.as_str())
        );
        assert_eq!(route.private_network_id, private_network.id);
        assert_eq!(route.route_table_id, route_table.id);
        assert_eq!(route.next_hop_id, next_hop.id);

        let subnets = service
            .list_subnets_for_private_network(&private_network.id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let route_tables = service
            .list_route_tables_for_private_network(&private_network.id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let next_hops = service
            .list_next_hops_for_private_network(&private_network.id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let routes = service
            .list_routes_for_route_table(&private_network.id, &route_table.id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(subnets.len(), 1);
        assert_eq!(route_tables.len(), 1);
        assert_eq!(next_hops.len(), 1);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination, "0.0.0.0/0");
    }

    #[tokio::test]
    async fn subnet_creation_rejects_out_of_network_and_overlapping_cidrs() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let private_network: PrivateNetworkRecord = read_json(
            service
                .create_private_network(
                    CreatePrivateNetworkRequest {
                        name: String::from("validation"),
                        cidr: String::from("10.70.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let route_table: RouteTableRecord = read_json(
            service
                .create_route_table(
                    &private_network.id,
                    CreateRouteTableRequest {
                        name: String::from("main"),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        service
            .create_subnet(
                &private_network.id,
                CreateSubnetRequest {
                    name: String::from("primary"),
                    cidr: String::from("10.70.1.0/24"),
                    route_table_id: Some(route_table.id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let outside = service
            .create_subnet(
                &private_network.id,
                CreateSubnetRequest {
                    name: String::from("outside"),
                    cidr: String::from("10.71.1.0/24"),
                    route_table_id: Some(route_table.id.to_string()),
                },
                &context,
            )
            .await
            .expect_err("subnet outside parent network should be rejected");
        assert!(
            outside
                .message
                .contains("contained within the private network cidr")
        );

        let overlapping = service
            .create_subnet(
                &private_network.id,
                CreateSubnetRequest {
                    name: String::from("overlap"),
                    cidr: String::from("10.70.1.128/25"),
                    route_table_id: Some(route_table.id.to_string()),
                },
                &context,
            )
            .await
            .expect_err("overlapping subnet should be rejected");
        assert!(overlapping.message.contains("overlaps existing subnet"));
    }

    #[tokio::test]
    async fn private_routes_reject_cross_network_next_hop_references() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let private_network_a: PrivateNetworkRecord = read_json(
            service
                .create_private_network(
                    CreatePrivateNetworkRequest {
                        name: String::from("network-a"),
                        cidr: String::from("10.80.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let private_network_b: PrivateNetworkRecord = read_json(
            service
                .create_private_network(
                    CreatePrivateNetworkRequest {
                        name: String::from("network-b"),
                        cidr: String::from("10.81.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let route_table_a: RouteTableRecord = read_json(
            service
                .create_route_table(
                    &private_network_a.id,
                    CreateRouteTableRequest {
                        name: String::from("main-a"),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let next_hop_b: NextHopRecord = read_json(
            service
                .create_next_hop(
                    &private_network_b.id,
                    CreateNextHopRequest {
                        name: String::from("local-b"),
                        kind: String::from("local"),
                        target: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let error = service
            .create_private_route(
                &private_network_a.id,
                &route_table_a.id,
                CreatePrivateRouteRequest {
                    destination: String::from("0.0.0.0/0"),
                    next_hop_id: next_hop_b.id.to_string(),
                },
                &context,
            )
            .await
            .expect_err("cross-network next hop should be rejected");
        assert!(error.message.contains("does not exist in private network"));
    }

    #[tokio::test]
    async fn private_network_connectivity_resources_capture_scope_and_persist() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_tenant("tenant-alpha");

        let private_network: PrivateNetworkRecord = read_json(
            service
                .create_private_network(
                    CreatePrivateNetworkRequest {
                        name: String::from("network-a"),
                        cidr: String::from("10.90.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let transit_network: PrivateNetworkRecord = read_json(
            service
                .create_private_network(
                    CreatePrivateNetworkRequest {
                        name: String::from("transit-hub"),
                        cidr: String::from("10.91.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let peer_network: PrivateNetworkRecord = read_json(
            service
                .create_private_network(
                    CreatePrivateNetworkRequest {
                        name: String::from("peer-network"),
                        cidr: String::from("10.92.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let route_table: RouteTableRecord = read_json(
            service
                .create_route_table(
                    &private_network.id,
                    CreateRouteTableRequest {
                        name: String::from("main"),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let subnet: SubnetRecord = read_json(
            service
                .create_subnet(
                    &private_network.id,
                    CreateSubnetRequest {
                        name: String::from("egress-a"),
                        cidr: String::from("10.90.1.0/24"),
                        route_table_id: Some(route_table.id.to_string()),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let nat_gateway: NatGatewayRecord = read_json(
            service
                .create_nat_gateway(
                    &private_network.id,
                    CreateNatGatewayRequest {
                        name: String::from("nat-a"),
                        tenant_id: None,
                        cell: String::from("use1-cell-a"),
                        public_ip: String::from("203.0.113.10"),
                        subnet_id: Some(subnet.id.to_string()),
                        route_table_ids: vec![route_table.id.to_string()],
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let transit_attachment: TransitAttachmentRecord = read_json(
            service
                .create_transit_attachment(
                    &private_network.id,
                    CreateTransitAttachmentRequest {
                        name: String::from("hub-link"),
                        tenant_id: Some(String::from("tenant-alpha")),
                        cell: String::from("use1-cell-a"),
                        transit_private_network_id: transit_network.id.to_string(),
                        transit_tenant_id: String::from("tenant-shared"),
                        transit_cell: String::from("use1-transit-b"),
                        route_table_ids: vec![route_table.id.to_string()],
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let vpn_connection: VpnConnectionRecord = read_json(
            service
                .create_vpn_connection(
                    &private_network.id,
                    CreateVpnConnectionRequest {
                        name: String::from("branch-link"),
                        tenant_id: None,
                        cell: String::from("use1-cell-a"),
                        gateway_address: String::from("198.51.100.7"),
                        remote_cidrs: vec![
                            String::from("172.16.0.0/16"),
                            String::from("192.168.50.0/24"),
                        ],
                        route_table_ids: vec![route_table.id.to_string()],
                        routing_mode: Some(String::from("bgp")),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let peering_connection: PeeringConnectionRecord = read_json(
            service
                .create_peering_connection(
                    &private_network.id,
                    CreatePeeringConnectionRequest {
                        name: String::from("peer-b"),
                        tenant_id: Some(String::from("tenant-alpha")),
                        cell: String::from("use1-cell-a"),
                        peer_private_network_id: peer_network.id.to_string(),
                        peer_tenant_id: String::from("tenant-beta"),
                        peer_cell: String::from("usw2-cell-b"),
                        route_table_ids: vec![route_table.id.to_string()],
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        assert_eq!(nat_gateway.tenant_id, "tenant-alpha");
        assert_eq!(nat_gateway.cell, "use1-cell-a");
        assert_eq!(nat_gateway.metadata.ownership_scope, OwnershipScope::Tenant);
        assert_eq!(
            nat_gateway.metadata.owner_id.as_deref(),
            Some("tenant-alpha")
        );
        assert_eq!(nat_gateway.subnet_id.as_ref(), Some(&subnet.id));
        assert_eq!(nat_gateway.route_table_ids, vec![route_table.id.clone()]);

        assert_eq!(transit_attachment.private_network_id, private_network.id);
        assert_eq!(
            transit_attachment.transit_private_network_id,
            transit_network.id
        );
        assert_eq!(transit_attachment.tenant_id, "tenant-alpha");
        assert_eq!(transit_attachment.cell, "use1-cell-a");
        assert_eq!(transit_attachment.transit_tenant_id, "tenant-shared");
        assert_eq!(transit_attachment.transit_cell, "use1-transit-b");
        assert_eq!(
            transit_attachment.route_table_ids,
            vec![route_table.id.clone()]
        );

        assert_eq!(vpn_connection.private_network_id, private_network.id);
        assert_eq!(vpn_connection.tenant_id, "tenant-alpha");
        assert_eq!(vpn_connection.cell, "use1-cell-a");
        assert_eq!(vpn_connection.gateway_address, "198.51.100.7");
        assert_eq!(
            vpn_connection.remote_cidrs,
            vec![
                String::from("172.16.0.0/16"),
                String::from("192.168.50.0/24"),
            ]
        );
        assert_eq!(vpn_connection.route_table_ids, vec![route_table.id.clone()]);
        assert_eq!(vpn_connection.routing_mode, "bgp");

        assert_eq!(peering_connection.private_network_id, private_network.id);
        assert_eq!(peering_connection.tenant_id, "tenant-alpha");
        assert_eq!(peering_connection.cell, "use1-cell-a");
        assert_eq!(peering_connection.peer_private_network_id, peer_network.id);
        assert_eq!(peering_connection.peer_tenant_id, "tenant-beta");
        assert_eq!(peering_connection.peer_cell, "usw2-cell-b");
        assert_eq!(
            peering_connection.route_table_ids,
            vec![route_table.id.clone()]
        );

        assert_eq!(
            service
                .list_nat_gateways_for_private_network(&private_network.id)
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            1
        );
        assert_eq!(
            service
                .list_transit_attachments_for_private_network(&private_network.id)
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            1
        );
        assert_eq!(
            service
                .list_vpn_connections_for_private_network(&private_network.id)
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            1
        );
        assert_eq!(
            service
                .list_peering_connections_for_private_network(&private_network.id)
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn connectivity_resources_fail_closed_on_scope_and_reference_errors() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_tenant("tenant-alpha");

        let private_network: PrivateNetworkRecord = read_json(
            service
                .create_private_network(
                    CreatePrivateNetworkRequest {
                        name: String::from("network-a"),
                        cidr: String::from("10.93.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let other_network: PrivateNetworkRecord = read_json(
            service
                .create_private_network(
                    CreatePrivateNetworkRequest {
                        name: String::from("network-b"),
                        cidr: String::from("10.94.0.0/16"),
                        attachments: Vec::new(),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let route_table: RouteTableRecord = read_json(
            service
                .create_route_table(
                    &private_network.id,
                    CreateRouteTableRequest {
                        name: String::from("main"),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let foreign_subnet: SubnetRecord = read_json(
            service
                .create_subnet(
                    &other_network.id,
                    CreateSubnetRequest {
                        name: String::from("foreign"),
                        cidr: String::from("10.94.1.0/24"),
                        route_table_id: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let tenant_mismatch = service
            .create_nat_gateway(
                &private_network.id,
                CreateNatGatewayRequest {
                    name: String::from("bad-tenant"),
                    tenant_id: Some(String::from("tenant-beta")),
                    cell: String::from("use1-cell-a"),
                    public_ip: String::from("203.0.113.11"),
                    subnet_id: None,
                    route_table_ids: vec![route_table.id.to_string()],
                },
                &context,
            )
            .await
            .expect_err("tenant mismatch should be rejected");
        assert!(tenant_mismatch.message.contains("tenant_id must match"));

        let foreign_subnet_error = service
            .create_nat_gateway(
                &private_network.id,
                CreateNatGatewayRequest {
                    name: String::from("bad-subnet"),
                    tenant_id: None,
                    cell: String::from("use1-cell-a"),
                    public_ip: String::from("203.0.113.12"),
                    subnet_id: Some(foreign_subnet.id.to_string()),
                    route_table_ids: vec![route_table.id.to_string()],
                },
                &context,
            )
            .await
            .expect_err("foreign subnet should be rejected");
        assert!(
            foreign_subnet_error
                .message
                .contains("does not exist in private network")
        );

        let transit_loop = service
            .create_transit_attachment(
                &private_network.id,
                CreateTransitAttachmentRequest {
                    name: String::from("loop"),
                    tenant_id: None,
                    cell: String::from("use1-cell-a"),
                    transit_private_network_id: private_network.id.to_string(),
                    transit_tenant_id: String::from("tenant-alpha"),
                    transit_cell: String::from("use1-cell-a"),
                    route_table_ids: vec![route_table.id.to_string()],
                },
                &context,
            )
            .await
            .expect_err("self transit attachment should be rejected");
        assert!(
            transit_loop
                .message
                .contains("must reference a different private network")
        );

        let vpn_empty = service
            .create_vpn_connection(
                &private_network.id,
                CreateVpnConnectionRequest {
                    name: String::from("vpn-empty"),
                    tenant_id: None,
                    cell: String::from("use1-cell-a"),
                    gateway_address: String::from("198.51.100.8"),
                    remote_cidrs: Vec::new(),
                    route_table_ids: vec![route_table.id.to_string()],
                    routing_mode: Some(String::from("static")),
                },
                &context,
            )
            .await
            .expect_err("vpn without remote cidrs should be rejected");
        assert!(vpn_empty.message.contains("remote_cidrs may not be empty"));

        let peering_loop = service
            .create_peering_connection(
                &private_network.id,
                CreatePeeringConnectionRequest {
                    name: String::from("peer-self"),
                    tenant_id: None,
                    cell: String::from("use1-cell-a"),
                    peer_private_network_id: private_network.id.to_string(),
                    peer_tenant_id: String::from("tenant-alpha"),
                    peer_cell: String::from("use1-cell-a"),
                    route_table_ids: vec![route_table.id.to_string()],
                },
                &context,
            )
            .await
            .expect_err("self peering should be rejected");
        assert!(
            peering_loop
                .message
                .contains("must reference a different private network")
        );
    }

    #[tokio::test]
    async fn abuse_quarantine_blocks_network_even_when_policy_allows() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_egress_rule(
                CreateEgressRuleRequest {
                    target_kind: String::from("cidr"),
                    target_value: String::from("10.0.0.0/8"),
                    action: String::from("allow"),
                    reason: String::from("allow private network"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut selector = BTreeMap::new();
        selector.insert(String::from("tier"), String::from("backend"));
        let _ = service
            .create_policy(
                CreatePolicyRequest {
                    name: String::from("backend-egress"),
                    selector,
                    default_action: Some(String::from("deny")),
                    mtls_mode: Some(String::from("strict")),
                    rules: vec![NetsecRule {
                        priority: 1,
                        action: String::from("allow"),
                        direction: String::from("egress"),
                        protocol: String::from("tcp"),
                        cidr: String::from("10.0.0.0/8"),
                        port_start: 443,
                        port_end: 443,
                        require_identity: true,
                    }],
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_service_identity(
                CreateServiceIdentityRequest {
                    subject: String::from("svc:api"),
                    mtls_cert_fingerprint: String::from("sha256:api-cert"),
                    labels: BTreeMap::new(),
                    allowed_private_networks: Vec::new(),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .abuse_quarantines
            .create(
                "abq_demo",
                AbuseQuarantineHookRecord {
                    subject_kind: String::from("service_identity"),
                    subject: String::from("svc:api"),
                    state: String::from("active"),
                    deny_network: true,
                    expires_at: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut labels = BTreeMap::new();
        labels.insert(String::from("tier"), String::from("backend"));
        let _ = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: Some(String::from("svc:api")),
                    destination: String::from("10.1.2.3"),
                    protocol: String::from("tcp"),
                    port: 443,
                    labels,
                    inspection_profile_id: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let audits = service
            .flow_audit
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].1.value.verdict, "deny");
        assert!(audits[0].1.value.reason.contains("abuse quarantine"));
    }

    #[tokio::test]
    async fn inspection_profile_blocks_geo_restricted_country() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_egress_rule(
                CreateEgressRuleRequest {
                    target_kind: String::from("cidr"),
                    target_value: String::from("10.0.0.0/8"),
                    action: String::from("allow"),
                    reason: String::from("allow private destinations"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_policy(
                CreatePolicyRequest {
                    name: String::from("open-backend"),
                    selector: BTreeMap::new(),
                    default_action: Some(String::from("allow")),
                    mtls_mode: Some(String::from("permissive")),
                    rules: Vec::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_inspection_profile(
                CreateInspectionProfileRequest {
                    name: String::from("geo-guard"),
                    blocked_countries: vec![String::from("CN")],
                    min_waf_score: Some(100),
                    max_bot_score: Some(900),
                    ddos_mode: Some(String::from("monitor")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let inspection_profile_id = service
            .inspection_profiles
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .id
            .to_string();

        let _ = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: None,
                    destination: String::from("10.1.1.1"),
                    protocol: String::from("tcp"),
                    port: 443,
                    labels: BTreeMap::new(),
                    inspection_profile_id: Some(inspection_profile_id),
                    source_country: Some(String::from("CN")),
                    waf_score: Some(500),
                    bot_score: Some(100),
                    ddos_suspected: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let audit = service
            .flow_audit
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .clone();
        assert_eq!(audit.verdict, "deny");
        assert!(audit.reason.contains("geo restriction"));
        assert_eq!(audit.source_country.as_deref(), Some("CN"));
    }

    #[tokio::test]
    async fn inspection_profile_blocks_on_waf_and_bot_thresholds() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_egress_rule(
                CreateEgressRuleRequest {
                    target_kind: String::from("cidr"),
                    target_value: String::from("10.0.0.0/8"),
                    action: String::from("allow"),
                    reason: String::from("allow private destinations"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_policy(
                CreatePolicyRequest {
                    name: String::from("open-backend"),
                    selector: BTreeMap::new(),
                    default_action: Some(String::from("allow")),
                    mtls_mode: Some(String::from("permissive")),
                    rules: Vec::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_inspection_profile(
                CreateInspectionProfileRequest {
                    name: String::from("waf-bot-guard"),
                    blocked_countries: Vec::new(),
                    min_waf_score: Some(400),
                    max_bot_score: Some(250),
                    ddos_mode: Some(String::from("monitor")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let inspection_profile_id = service
            .inspection_profiles
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .id
            .to_string();

        let _ = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: None,
                    destination: String::from("10.1.1.1"),
                    protocol: String::from("tcp"),
                    port: 443,
                    labels: BTreeMap::new(),
                    inspection_profile_id: Some(inspection_profile_id.clone()),
                    source_country: Some(String::from("US")),
                    waf_score: Some(200),
                    bot_score: Some(100),
                    ddos_suspected: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_audits = service
            .flow_audit
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let waf_audit = first_audits
            .iter()
            .find(|entry| entry.reason.contains("waf threshold"))
            .unwrap_or_else(|| panic!("expected waf threshold audit entry"));
        assert_eq!(waf_audit.verdict, "deny");

        let _ = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: None,
                    destination: String::from("10.1.1.1"),
                    protocol: String::from("tcp"),
                    port: 443,
                    labels: BTreeMap::new(),
                    inspection_profile_id: Some(inspection_profile_id),
                    source_country: Some(String::from("US")),
                    waf_score: Some(500),
                    bot_score: Some(800),
                    ddos_suspected: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let audits = service
            .flow_audit
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        assert_eq!(audits.len(), 2);
        let bot_audit = audits
            .iter()
            .find(|entry| entry.reason.contains("bot score"))
            .unwrap_or_else(|| panic!("expected bot score audit entry"));
        assert_eq!(bot_audit.verdict, "deny");
    }

    #[tokio::test]
    async fn flow_audit_query_filters_results() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_egress_rule(
                CreateEgressRuleRequest {
                    target_kind: String::from("cidr"),
                    target_value: String::from("10.0.0.0/8"),
                    action: String::from("allow"),
                    reason: String::from("allow private network"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut selector = BTreeMap::new();
        selector.insert(String::from("tier"), String::from("backend"));
        let _ = service
            .create_policy(
                CreatePolicyRequest {
                    name: String::from("backend-egress"),
                    selector,
                    default_action: Some(String::from("deny")),
                    mtls_mode: Some(String::from("strict")),
                    rules: vec![NetsecRule {
                        priority: 1,
                        action: String::from("allow"),
                        direction: String::from("egress"),
                        protocol: String::from("tcp"),
                        cidr: String::from("10.0.0.0/8"),
                        port_start: 443,
                        port_end: 443,
                        require_identity: true,
                    }],
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_service_identity(
                CreateServiceIdentityRequest {
                    subject: String::from("svc:api"),
                    mtls_cert_fingerprint: String::from("sha256:api-cert"),
                    labels: BTreeMap::new(),
                    allowed_private_networks: Vec::new(),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut labels = BTreeMap::new();
        labels.insert(String::from("tier"), String::from("backend"));
        let _ = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: Some(String::from("svc:api")),
                    destination: String::from("10.1.2.3"),
                    protocol: String::from("tcp"),
                    port: 443,
                    labels: labels.clone(),
                    inspection_profile_id: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: Some(String::from("svc:api")),
                    destination: String::from("10.1.2.3"),
                    protocol: String::from("tcp"),
                    port: 80,
                    labels,
                    inspection_profile_id: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let query = parse_flow_audit_query(&BTreeMap::from([
            (String::from("verdict"), String::from("deny")),
            (String::from("source_identity"), String::from("svc:api")),
            (String::from("limit"), String::from("1")),
        ]))
        .unwrap_or_else(|error| panic!("{error}"));
        let response = service
            .list_flow_audit(&query)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let payload: Value =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));
        let values = payload
            .as_array()
            .unwrap_or_else(|| panic!("expected JSON array"));
        assert_eq!(values.len(), 1);
        assert_eq!(
            values[0]
                .get("verdict")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            "deny"
        );
    }

    #[tokio::test]
    async fn flow_audit_summary_aggregates_allow_and_deny_counts() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_egress_rule(
                CreateEgressRuleRequest {
                    target_kind: String::from("cidr"),
                    target_value: String::from("10.0.0.0/8"),
                    action: String::from("allow"),
                    reason: String::from("allow private network"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut selector = BTreeMap::new();
        selector.insert(String::from("tier"), String::from("backend"));
        let _ = service
            .create_policy(
                CreatePolicyRequest {
                    name: String::from("backend-egress"),
                    selector,
                    default_action: Some(String::from("deny")),
                    mtls_mode: Some(String::from("strict")),
                    rules: vec![NetsecRule {
                        priority: 1,
                        action: String::from("allow"),
                        direction: String::from("egress"),
                        protocol: String::from("tcp"),
                        cidr: String::from("10.0.0.0/8"),
                        port_start: 443,
                        port_end: 443,
                        require_identity: true,
                    }],
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_service_identity(
                CreateServiceIdentityRequest {
                    subject: String::from("svc:api"),
                    mtls_cert_fingerprint: String::from("sha256:api-cert"),
                    labels: BTreeMap::new(),
                    allowed_private_networks: Vec::new(),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut labels = BTreeMap::new();
        labels.insert(String::from("tier"), String::from("backend"));
        let _ = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: Some(String::from("svc:api")),
                    destination: String::from("10.1.2.3"),
                    protocol: String::from("tcp"),
                    port: 443,
                    labels: labels.clone(),
                    inspection_profile_id: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: Some(String::from("svc:api")),
                    destination: String::from("10.1.2.3"),
                    protocol: String::from("tcp"),
                    port: 80,
                    labels,
                    inspection_profile_id: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let query = parse_flow_audit_query(&BTreeMap::from([(
            String::from("source_identity"),
            String::from("svc:api"),
        )]))
        .unwrap_or_else(|error| panic!("{error}"));
        let response = service
            .summarize_flow_audit(&query)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let payload: Value =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(payload["total"].as_u64().unwrap_or_default(), 2);
        assert_eq!(payload["allow"].as_u64().unwrap_or_default(), 1);
        assert_eq!(payload["deny"].as_u64().unwrap_or_default(), 1);
        assert!(
            payload["top_reasons"]
                .as_array()
                .map(|values| !values.is_empty())
                .unwrap_or(false)
        );
    }

    #[tokio::test]
    async fn netsec_summary_reports_policy_ipset_and_flow_breakdowns() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let metadata = |seed: &str| {
            ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(seed.to_owned()),
                sha256_hex(seed.as_bytes()),
            )
        };

        let policy_id = NetPolicyId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .policies
            .create(
                policy_id.as_str(),
                NetsecPolicy {
                    id: policy_id.clone(),
                    name: String::from("allow-backend"),
                    selector: BTreeMap::new(),
                    default_action: String::from("allow"),
                    mtls_mode: String::from("strict"),
                    rules: vec![
                        NetsecRule {
                            priority: 1,
                            action: String::from("allow"),
                            direction: String::from("egress"),
                            protocol: String::from("tcp"),
                            cidr: String::from("10.0.0.0/8"),
                            port_start: 443,
                            port_end: 443,
                            require_identity: false,
                        },
                        NetsecRule {
                            priority: 2,
                            action: String::from("deny"),
                            direction: String::from("egress"),
                            protocol: String::from("tcp"),
                            cidr: String::from("0.0.0.0/0"),
                            port_start: 22,
                            port_end: 22,
                            require_identity: false,
                        },
                    ],
                    metadata: metadata("policy-1"),
                    change_authorization: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let ipset_id = IpSetId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .ip_sets
            .create(
                ipset_id.as_str(),
                super::IpSetRecord {
                    id: ipset_id.clone(),
                    name: String::from("internal"),
                    cidrs: vec![String::from("10.0.0.0/8"), String::from("192.168.0.0/16")],
                    metadata: metadata("ipset-1"),
                    change_authorization: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let allow_flow_id = FlowAuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .flow_audit
            .create(
                allow_flow_id.as_str(),
                super::FlowAuditRecord {
                    id: allow_flow_id.clone(),
                    source_identity: Some(String::from("svc:api")),
                    destination: String::from("10.1.2.3"),
                    protocol: String::from("tcp"),
                    port: 443,
                    verdict: String::from("allow"),
                    policy_id: Some(policy_id.clone()),
                    inspection_profile_id: None,
                    inspection_reason: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: false,
                    reason: String::from("matched allow rule"),
                    observed_at: OffsetDateTime::now_utc(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let deny_flow_id = FlowAuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .flow_audit
            .create(
                deny_flow_id.as_str(),
                super::FlowAuditRecord {
                    id: deny_flow_id.clone(),
                    source_identity: Some(String::from("svc:api")),
                    destination: String::from("8.8.8.8"),
                    protocol: String::from("tcp"),
                    port: 443,
                    verdict: String::from("deny"),
                    policy_id: Some(policy_id),
                    inspection_profile_id: None,
                    inspection_reason: Some(String::from("waf threshold")),
                    source_country: Some(String::from("US")),
                    waf_score: Some(120),
                    bot_score: None,
                    ddos_suspected: false,
                    reason: String::from("blocked by inspection"),
                    observed_at: OffsetDateTime::now_utc(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let critical_flow_id = FlowAuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .flow_audit
            .create(
                critical_flow_id.as_str(),
                super::FlowAuditRecord {
                    id: critical_flow_id.clone(),
                    source_identity: Some(String::from("svc:edge")),
                    destination: String::from("10.2.3.4"),
                    protocol: String::from("tcp"),
                    port: 443,
                    verdict: String::from("deny"),
                    policy_id: None,
                    inspection_profile_id: None,
                    inspection_reason: Some(String::from("ddos suspected")),
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: true,
                    reason: String::from("blocked for ddos"),
                    observed_at: OffsetDateTime::now_utc(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .summary_report()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload: Value = read_json(response).await;

        assert_eq!(payload["policies"]["total"].as_u64().unwrap_or_default(), 1);
        assert_eq!(
            payload["policies"]["total_rules"]
                .as_u64()
                .unwrap_or_default(),
            2
        );
        assert_eq!(payload["ip_sets"]["total"].as_u64().unwrap_or_default(), 1);
        assert_eq!(
            payload["ip_sets"]["total_cidrs"]
                .as_u64()
                .unwrap_or_default(),
            2
        );
        assert_eq!(
            payload["flow_audit"]["total"].as_u64().unwrap_or_default(),
            3
        );
        assert_eq!(
            payload["flow_audit"]["allow"].as_u64().unwrap_or_default(),
            1
        );
        assert_eq!(
            payload["flow_audit"]["deny"].as_u64().unwrap_or_default(),
            2
        );

        let default_allow = payload["policies"]["default_actions"]
            .as_array()
            .unwrap_or_else(|| panic!("expected default_actions array"))
            .iter()
            .find(|item| item["key"] == "allow")
            .and_then(|item| item["count"].as_u64())
            .unwrap_or_default();
        assert_eq!(default_allow, 1);

        let severity = payload["flow_audit"]["severity"]
            .as_array()
            .unwrap_or_else(|| panic!("expected severity array"));
        let critical = severity
            .iter()
            .find(|item| item["key"] == "critical")
            .and_then(|item| item["count"].as_u64())
            .unwrap_or_default();
        let high = severity
            .iter()
            .find(|item| item["key"] == "high")
            .and_then(|item| item["count"].as_u64())
            .unwrap_or_default();
        let low = severity
            .iter()
            .find(|item| item["key"] == "low")
            .and_then(|item| item["count"].as_u64())
            .unwrap_or_default();
        assert_eq!(critical, 1);
        assert_eq!(high, 1);
        assert_eq!(low, 1);
    }

    #[tokio::test]
    async fn matching_policies_are_selected_by_creation_time() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_egress_rule(
                CreateEgressRuleRequest {
                    target_kind: String::from("cidr"),
                    target_value: String::from("10.0.0.0/8"),
                    action: String::from("allow"),
                    reason: String::from("allow private network"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let allow_id = NetPolicyId::parse("npl_zzzzzzzzzzzzzzzzzzzzzzzzzz").unwrap();
        let deny_id = NetPolicyId::parse("npl_aaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let old_metadata = ResourceMetadata {
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            lifecycle: ResourceLifecycleState::Pending,
            ownership_scope: OwnershipScope::Platform,
            owner_id: Some(allow_id.to_string()),
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            deleted_at: None,
            etag: sha256_hex(allow_id.as_str().as_bytes()),
        };
        let new_metadata = ResourceMetadata {
            created_at: OffsetDateTime::UNIX_EPOCH + Duration::seconds(1),
            updated_at: OffsetDateTime::UNIX_EPOCH + Duration::seconds(1),
            lifecycle: ResourceLifecycleState::Pending,
            ownership_scope: OwnershipScope::Platform,
            owner_id: Some(deny_id.to_string()),
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            deleted_at: None,
            etag: sha256_hex(deny_id.as_str().as_bytes()),
        };

        service
            .policies
            .create(
                allow_id.as_str(),
                NetsecPolicy {
                    id: allow_id.clone(),
                    name: String::from("old-allow"),
                    selector: BTreeMap::new(),
                    default_action: String::from("allow"),
                    mtls_mode: String::from("permissive"),
                    rules: Vec::new(),
                    metadata: old_metadata,
                    change_authorization: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .policies
            .create(
                deny_id.as_str(),
                NetsecPolicy {
                    id: deny_id.clone(),
                    name: String::from("new-deny"),
                    selector: BTreeMap::new(),
                    default_action: String::from("deny"),
                    mtls_mode: String::from("permissive"),
                    rules: Vec::new(),
                    metadata: new_metadata,
                    change_authorization: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: None,
                    destination: String::from("10.1.2.3"),
                    protocol: String::from("tcp"),
                    port: 443,
                    labels: BTreeMap::new(),
                    inspection_profile_id: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let payload: Value =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            payload
                .get("verdict")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            "allow"
        );
        assert_eq!(
            payload
                .get("policy_id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            allow_id.as_str()
        );
    }

    #[tokio::test]
    async fn policy_rules_can_resolve_ipset_targets() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NetsecService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_egress_rule(
                CreateEgressRuleRequest {
                    target_kind: String::from("cidr"),
                    target_value: String::from("10.0.0.0/8"),
                    action: String::from("allow"),
                    reason: String::from("allow private network"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let ipset_id = super::IpSetId::parse("ips_zzzzzzzzzzzzzzzzzzzzzzzzzz").unwrap();
        service
            .ip_sets
            .create(
                ipset_id.as_str(),
                super::IpSetRecord {
                    id: ipset_id.clone(),
                    name: String::from("private-range"),
                    cidrs: vec![String::from("10.0.0.0/8")],
                    metadata: ResourceMetadata {
                        created_at: OffsetDateTime::UNIX_EPOCH,
                        updated_at: OffsetDateTime::UNIX_EPOCH,
                        lifecycle: ResourceLifecycleState::Pending,
                        ownership_scope: OwnershipScope::Platform,
                        owner_id: Some(ipset_id.to_string()),
                        labels: BTreeMap::new(),
                        annotations: BTreeMap::new(),
                        deleted_at: None,
                        etag: sha256_hex(ipset_id.as_str().as_bytes()),
                    },
                    change_authorization: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let policy_id = NetPolicyId::parse("npl_yyyyyyyyyyyyyyyyyyyyyyyyyy").unwrap();
        service
            .policies
            .create(
                policy_id.as_str(),
                NetsecPolicy {
                    id: policy_id.clone(),
                    name: String::from("ipset-policy"),
                    selector: BTreeMap::new(),
                    default_action: String::from("deny"),
                    mtls_mode: String::from("permissive"),
                    rules: vec![NetsecRule {
                        priority: 1,
                        action: String::from("allow"),
                        direction: String::from("egress"),
                        protocol: String::from("tcp"),
                        cidr: format!("ipset:{}", ipset_id),
                        port_start: 443,
                        port_end: 443,
                        require_identity: false,
                    }],
                    metadata: ResourceMetadata {
                        created_at: OffsetDateTime::UNIX_EPOCH + Duration::seconds(1),
                        updated_at: OffsetDateTime::UNIX_EPOCH + Duration::seconds(1),
                        lifecycle: ResourceLifecycleState::Pending,
                        ownership_scope: OwnershipScope::Platform,
                        owner_id: Some(policy_id.to_string()),
                        labels: BTreeMap::new(),
                        annotations: BTreeMap::new(),
                        deleted_at: None,
                        etag: sha256_hex(policy_id.as_str().as_bytes()),
                    },
                    change_authorization: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .verify_policy(
                PolicyVerifyRequest {
                    source_identity: None,
                    destination: String::from("10.1.2.3"),
                    protocol: String::from("tcp"),
                    port: 443,
                    labels: BTreeMap::new(),
                    inspection_profile_id: None,
                    source_country: None,
                    waf_score: None,
                    bot_score: None,
                    ddos_suspected: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let payload: Value =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            payload
                .get("verdict")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            "allow"
        );
        assert_eq!(
            payload
                .get("policy_id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            policy_id.as_str()
        );
    }

    #[test]
    fn cidr_match_handles_boundaries() {
        let in_range = super::ipv4_in_cidr(
            "192.168.1.44"
                .parse::<Ipv4Addr>()
                .unwrap_or_else(|error| panic!("{error}")),
            "192.168.1.0/24",
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let out_of_range = super::ipv4_in_cidr(
            "192.168.2.44"
                .parse::<Ipv4Addr>()
                .unwrap_or_else(|error| panic!("{error}")),
            "192.168.1.0/24",
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(in_range);
        assert!(!out_of_range);
    }

    proptest! {
        #[test]
        fn cidr_parser_accepts_valid_ipv4_ranges(ip in any::<u32>(), prefix in 0_u8..=32_u8) {
            let address = Ipv4Addr::from(ip);
            let cidr = format!("{address}/{prefix}");
            let parsed = super::parse_ipv4_cidr(&cidr);
            prop_assert!(parsed.is_ok());
        }
    }
}
