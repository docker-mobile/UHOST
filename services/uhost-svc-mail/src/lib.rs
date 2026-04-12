//! Mail platform service.
//!
//! This service owns mail-domain onboarding, DKIM/SPF/DMARC record generation,
//! SMTP relay and inbound routing hooks, message queue/retry state transitions,
//! and reputation signaling into abuse/trust-safety systems.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use http::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uhost_api::{ApiBody, json_response, parse_json, parse_query, path_segments};
use uhost_core::{PlatformError, RequestContext, Result, sha256_hex, validate_domain_name};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{AuditLog, DocumentStore, DurableOutbox, StoredDocument};
use uhost_types::{
    AuditActor, AuditId, ChangeRequestId, DeadLetterId, EventHeader, EventPayload,
    GovernanceChangeAuthorization, GovernanceRequestProvenance, MailDomainId, MailRouteId,
    OwnershipScope, PlatformEvent, ResourceMetadata, RouteId, ServiceEvent, ZoneId,
};

const GOVERNANCE_CHANGE_REQUEST_HEADER: &str = "x-uhost-change-request-id";

/// Mail domain and auth record model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailDomainRecord {
    /// Domain identifier.
    pub id: MailDomainId,
    /// Managed mail domain.
    pub domain: String,
    /// Optional DNS zone identifier.
    pub zone_id: Option<String>,
    /// Current verification state.
    pub verified: bool,
    /// DNS automation provider hint.
    pub dns_provider: String,
    /// DKIM selector prefix.
    pub dkim_selector: String,
    /// SPF TXT value.
    pub spf_value: String,
    /// DMARC TXT value.
    pub dmarc_value: String,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the domain mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// SMTP relay route hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRouteRecord {
    /// Relay route identifier.
    pub id: MailRouteId,
    /// Owning domain.
    pub domain_id: MailDomainId,
    /// Upstream relay destination.
    pub destination: String,
    /// Auth mode (for example `mtls`, `smtp_auth`).
    pub auth_mode: String,
    /// Whether the route is active.
    pub enabled: bool,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the relay mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// Inbound routing hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundRouteRecord {
    /// Inbound route identifier.
    pub id: RouteId,
    /// Owning domain.
    pub domain_id: MailDomainId,
    /// Recipient wildcard pattern (`*`, `support@`, etc.).
    pub recipient_pattern: String,
    /// Delivery target reference.
    pub target: String,
    /// Whether this route is active.
    pub enabled: bool,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    /// Governance authorization bound to the inbound-route mutation when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// Message delivery state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageState {
    /// Waiting for delivery.
    Queued,
    /// Delivery in progress.
    Delivering,
    /// Delivery completed.
    Delivered,
    /// Delivery failed.
    Failed,
    /// Retry budget exhausted and moved to dead-letter queue.
    DeadLettered,
}

/// Message event record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageEventRecord {
    /// Message event identifier.
    pub id: AuditId,
    /// Owning domain.
    pub domain_id: MailDomainId,
    /// `outbound` or `inbound`.
    pub direction: String,
    /// Sender address.
    pub from: String,
    /// Recipient address.
    pub to: String,
    /// SHA-256 hash of subject line.
    pub subject_hash: String,
    /// Current state.
    pub state: MessageState,
    /// Delivery attempts.
    pub attempts: u32,
    /// Retry budget ceiling.
    #[serde(default = "default_message_max_attempts")]
    pub max_attempts: u32,
    /// Earliest retry time.
    pub next_attempt_at: Option<OffsetDateTime>,
    /// Last error if present.
    pub last_error: Option<String>,
    /// Update timestamp.
    pub updated_at: OffsetDateTime,
}

/// Dead-letter capture for messages that exhausted retries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailDeadLetterRecord {
    /// Dead-letter identifier.
    pub id: DeadLetterId,
    /// Original message id.
    pub message_id: AuditId,
    /// Owning domain.
    pub domain_id: MailDomainId,
    /// Delivery direction.
    pub direction: String,
    /// Sender address.
    pub from: String,
    /// Recipient address.
    pub to: String,
    /// Attempts consumed before dead-lettering.
    pub attempts: u32,
    /// Last failure reason.
    pub last_error: String,
    /// Capture timestamp.
    pub captured_at: OffsetDateTime,
    /// Replay count.
    pub replay_count: u32,
    /// Last replay timestamp.
    pub last_replayed_at: Option<OffsetDateTime>,
    /// Last replay reason.
    pub last_replay_reason: Option<String>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Summary for one dispatch sweep execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchSummary {
    /// Number of queued/failed messages inspected.
    pub inspected: usize,
    /// Successfully delivered in this sweep.
    pub delivered: usize,
    /// Failed but still retryable.
    pub failed: usize,
    /// Moved to dead-letter queue.
    pub dead_lettered: usize,
    /// Skipped because they were not yet due.
    pub skipped_not_due: usize,
}

/// Reputation state for a mail domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReputationRecord {
    /// Domain identifier.
    pub domain_id: MailDomainId,
    /// Reputation score. Lower values indicate higher abuse risk.
    pub score: i32,
    /// Whether outbound relay is suspended.
    pub suspended: bool,
    /// Last updated timestamp.
    pub updated_at: OffsetDateTime,
    /// Last reason.
    pub reason: Option<String>,
}

/// Aggregated view of the persisted mail state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailSummary {
    pub domain_count: usize,
    pub verified_domain_count: usize,
    pub relay_route_count: usize,
    pub inbound_route_count: usize,
    pub message_event_count: usize,
    pub message_state_counts: BTreeMap<String, usize>,
    pub dead_letter_count: usize,
    pub dead_letter_total_replays: u32,
    pub reputation_record_count: usize,
    pub reputation_suspended_count: usize,
    pub dns_zone_count: usize,
    pub dns_zone_verified_count: usize,
    pub dns_record_count: usize,
    pub dns_provider_task_count: usize,
    pub abuse_quarantine_count: usize,
    pub abuse_quarantine_denies: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateDomainRequest {
    domain: String,
    zone_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateRelayRouteRequest {
    domain_id: String,
    destination: String,
    auth_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateInboundRouteRequest {
    domain_id: String,
    recipient_pattern: String,
    target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateMessageEventRequest {
    domain_id: String,
    direction: String,
    from: String,
    to: String,
    subject: String,
    max_attempts: Option<u32>,
    deliver_after_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AdjustReputationRequest {
    delta: i32,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DispatchSweepRequest {
    limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReplayDeadLetterRequest {
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VerifyDomainAuthRequest {
    reconcile_missing: Option<bool>,
    ttl: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DomainAuthRecordStatus {
    purpose: String,
    record_type: String,
    name: String,
    value: String,
    present: bool,
    record_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DomainAuthRecordView {
    domain_id: String,
    domain: String,
    verified: bool,
    zone_id: Option<String>,
    dns_provider: String,
    required_records: Vec<DomainAuthRecordStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VerifyDomainAuthResponse {
    domain_id: String,
    domain: String,
    zone_id: String,
    verified: bool,
    reconciled_records: usize,
    stale_records_removed: usize,
    missing_records: usize,
    checked_at: OffsetDateTime,
    records: Vec<DomainAuthRecordStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DnsRecordHook {
    id: String,
    zone_id: String,
    name: String,
    record_type: String,
    value: String,
    ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DnsZoneHook {
    id: String,
    domain: String,
    verified: bool,
    metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DnsProviderTaskHook {
    id: String,
    provider: String,
    action: String,
    resource_id: String,
    payload: serde_json::Value,
    status: String,
    #[serde(default)]
    attempt_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_attempt_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_attempt_at: Option<OffsetDateTime>,
    last_error: Option<String>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsRecordDeliveryState {
    record_id: String,
    provider_task_id: String,
    provider: String,
    status: String,
    attempt_count: u32,
    last_attempt_at: Option<OffsetDateTime>,
    next_attempt_at: Option<OffsetDateTime>,
    last_error: Option<String>,
    updated_at: OffsetDateTime,
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
    deny_mail_relay: bool,
    expires_at: Option<OffsetDateTime>,
    released_at: Option<OffsetDateTime>,
    released_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GovernanceChangeRequestMirror {
    id: ChangeRequestId,
    state: String,
    #[serde(default, flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchOutcome {
    Delivered,
    FailedRetryable,
    DeadLettered,
}

/// Mail service implementation.
#[derive(Debug, Clone)]
pub struct MailService {
    domains: DocumentStore<MailDomainRecord>,
    relay_routes: DocumentStore<RelayRouteRecord>,
    inbound_routes: DocumentStore<InboundRouteRecord>,
    message_events: DocumentStore<MessageEventRecord>,
    dead_letters: DocumentStore<MailDeadLetterRecord>,
    reputation: DocumentStore<ReputationRecord>,
    dns_zones: DocumentStore<DnsZoneHook>,
    dns_records: DocumentStore<DnsRecordHook>,
    dns_provider_tasks: DocumentStore<DnsProviderTaskHook>,
    abuse_quarantines: DocumentStore<AbuseQuarantineHookRecord>,
    governance_change_requests: DocumentStore<GovernanceChangeRequestMirror>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    state_root: PathBuf,
}

impl MailService {
    /// Open mail state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("mail");
        let abuse_quarantine_path = state_root.as_ref().join("abuse").join("quarantines.json");
        Ok(Self {
            domains: DocumentStore::open(root.join("domains.json")).await?,
            relay_routes: DocumentStore::open(root.join("relay_routes.json")).await?,
            inbound_routes: DocumentStore::open(root.join("inbound_routes.json")).await?,
            message_events: DocumentStore::open(root.join("message_events.json")).await?,
            dead_letters: DocumentStore::open(root.join("dead_letters.json")).await?,
            reputation: DocumentStore::open(root.join("reputation.json")).await?,
            dns_zones: DocumentStore::open(state_root.as_ref().join("dns").join("zones.json"))
                .await?,
            dns_records: DocumentStore::open(state_root.as_ref().join("dns").join("records.json"))
                .await?,
            dns_provider_tasks: DocumentStore::open(
                state_root.as_ref().join("dns").join("provider_tasks.json"),
            )
            .await?,
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

    async fn validate_domain_zone_binding(
        &self,
        zone_id: &str,
        domain: &str,
    ) -> Result<DnsZoneHook> {
        let zone_id = ZoneId::parse(zone_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid zone_id").with_detail(error.to_string())
        })?;
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
        if zone_domain != domain {
            return Err(PlatformError::forbidden(
                "zone_id is not authorized for this mail domain",
            ));
        }

        Ok(zone)
    }

    async fn create_domain(
        &self,
        request: CreateDomainRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_domain_authorized(request, context, None).await
    }

    async fn create_domain_authorized(
        &self,
        request: CreateDomainRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        let domain = validate_domain_name(&request.domain)?;
        let zone_id = normalize_optional_zone_id(request.zone_id)?;
        if let Some(zone_id) = zone_id.as_deref() {
            let _ = self.validate_domain_zone_binding(zone_id, &domain).await?;
        }
        let id = MailDomainId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate mail domain id")
                .with_detail(error.to_string())
        })?;
        let selector = format!("s1.{}", id.as_str());
        let dkim_value = format!("v=DKIM1; k=rsa; p={}", sha256_hex(selector.as_bytes()));
        let mut record = MailDomainRecord {
            id: id.clone(),
            domain: domain.clone(),
            zone_id,
            verified: false,
            dns_provider: String::from("cloudflare"),
            dkim_selector: selector.clone(),
            spf_value: String::from("v=spf1 include:_spf.uhost.example -all"),
            dmarc_value: format!("v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}"),
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                mail_domain_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "mail.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.domains.create(id.as_str(), record.clone()).await?;
        self.reputation
            .create(
                id.as_str(),
                ReputationRecord {
                    domain_id: id.clone(),
                    score: 100,
                    suspended: false,
                    updated_at: OffsetDateTime::now_utc(),
                    reason: None,
                },
            )
            .await?;
        let mut created_details = serde_json::json!({
            "domain": record.domain,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut created_details, authorization);
        }
        self.append_event(
            "mail.domain.created.v1",
            "mail_domain",
            id.as_str(),
            "created",
            created_details,
            context,
        )
        .await?;
        let mut auth_record_details = serde_json::json!({
            "dkim": {
                "name": format!("{}._domainkey", selector),
                "value": dkim_value,
            },
            "spf": {
                "name": "@",
                "value": record.spf_value,
            },
            "dmarc": {
                "name": "_dmarc",
                "value": record.dmarc_value,
            },
            "zone_id": record.zone_id,
            "provider": record.dns_provider,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut auth_record_details, authorization);
        }
        self.append_event(
            "mail.domain.auth_records.v1",
            "mail_auth_records",
            id.as_str(),
            "generated",
            auth_record_details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_relay_route(
        &self,
        request: CreateRelayRouteRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_relay_route_authorized(request, context, None)
            .await
    }

    async fn create_relay_route_authorized(
        &self,
        request: CreateRelayRouteRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        let destination = trimmed_nonempty(request.destination, "destination")?;
        let auth_mode = trimmed_nonempty(request.auth_mode, "auth_mode")?;
        let domain_id = MailDomainId::parse(request.domain_id).map_err(|error| {
            PlatformError::invalid("invalid domain_id").with_detail(error.to_string())
        })?;
        let _ = self
            .domains
            .get(domain_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("domain does not exist"))?;

        let id = MailRouteId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate relay route id")
                .with_detail(error.to_string())
        })?;
        let mut record = RelayRouteRecord {
            id: id.clone(),
            domain_id,
            destination,
            auth_mode,
            enabled: true,
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                relay_route_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "mail.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.relay_routes
            .create(id.as_str(), record.clone())
            .await?;
        let mut details = serde_json::json!({
            "destination": record.destination,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "mail.relay_route.created.v1",
            "relay_route",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_inbound_route(
        &self,
        request: CreateInboundRouteRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        self.create_inbound_route_authorized(request, context, None)
            .await
    }

    async fn create_inbound_route_authorized(
        &self,
        request: CreateInboundRouteRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<Response<ApiBody>> {
        let recipient_pattern = trimmed_nonempty(request.recipient_pattern, "recipient_pattern")?;
        let target = trimmed_nonempty(request.target, "target")?;
        let domain_id = MailDomainId::parse(request.domain_id).map_err(|error| {
            PlatformError::invalid("invalid domain_id").with_detail(error.to_string())
        })?;
        let _ = self
            .domains
            .get(domain_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("domain does not exist"))?;

        let id = RouteId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate inbound route id")
                .with_detail(error.to_string())
        })?;
        let mut record = InboundRouteRecord {
            id: id.clone(),
            domain_id,
            recipient_pattern,
            target,
            enabled: true,
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                inbound_route_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "mail.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.inbound_routes
            .create(id.as_str(), record.clone())
            .await?;
        let mut details = serde_json::json!({
            "target": record.target,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "mail.inbound_route.created.v1",
            "inbound_route",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_message_event(
        &self,
        request: CreateMessageEventRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let direction = normalize_direction(&request.direction)?;
        let from = trimmed_nonempty(request.from, "from")?;
        let to = trimmed_nonempty(request.to, "to")?;
        let domain_id = MailDomainId::parse(request.domain_id).map_err(|error| {
            PlatformError::invalid("invalid domain_id").with_detail(error.to_string())
        })?;
        let _ = self
            .domains
            .get(domain_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("domain does not exist"))?;

        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate message event id")
                .with_detail(error.to_string())
        })?;
        let record = MessageEventRecord {
            id: id.clone(),
            domain_id,
            direction,
            from,
            to,
            subject_hash: sha256_hex(request.subject.as_bytes()),
            state: MessageState::Queued,
            attempts: 0,
            max_attempts: request
                .max_attempts
                .unwrap_or(default_message_max_attempts())
                .clamp(1, 20),
            next_attempt_at: request.deliver_after_seconds.map(|seconds| {
                OffsetDateTime::now_utc() + Duration::seconds(i64::from(seconds.clamp(1, 86_400)))
            }),
            last_error: None,
            updated_at: OffsetDateTime::now_utc(),
        };
        self.message_events
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "mail.message.queued.v1",
            "message_event",
            id.as_str(),
            "queued",
            serde_json::json!({
                "direction": record.direction,
                "domain_id": record.domain_id,
                "max_attempts": record.max_attempts,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn dispatch_message(
        &self,
        message_id: &str,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let message_id = AuditId::parse(message_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid message id").with_detail(error.to_string())
        })?;
        let (record, _) = self
            .dispatch_message_event(message_id.as_str(), context)
            .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn dispatch_sweep(
        &self,
        request: DispatchSweepRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let now = OffsetDateTime::now_utc() - Duration::minutes(5);
        let limit = request.limit.unwrap_or(100).clamp(1, 1000);
        let mut candidates = self
            .message_events
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| matches!(record.state, MessageState::Queued | MessageState::Failed))
            .collect::<Vec<_>>();
        candidates.sort_by_key(|record| {
            record
                .next_attempt_at
                .unwrap_or(record.updated_at)
                .unix_timestamp_nanos()
        });
        let selected = candidates
            .into_iter()
            .take(limit)
            .map(|record| record.id)
            .collect::<Vec<_>>();

        let mut summary = DispatchSummary {
            inspected: selected.len(),
            delivered: 0,
            failed: 0,
            dead_lettered: 0,
            skipped_not_due: 0,
        };
        for message_id in selected {
            let stored = self
                .message_events
                .get(message_id.as_str())
                .await?
                .ok_or_else(|| PlatformError::not_found("message missing during dispatch sweep"))?;
            if let Some(next_attempt_at) = stored.value.next_attempt_at
                && next_attempt_at > now
            {
                summary.skipped_not_due = summary.skipped_not_due.saturating_add(1);
                continue;
            }
            let (_, outcome) = self
                .dispatch_message_event(message_id.as_str(), context)
                .await?;
            match outcome {
                DispatchOutcome::Delivered => {
                    summary.delivered = summary.delivered.saturating_add(1);
                }
                DispatchOutcome::FailedRetryable => {
                    summary.failed = summary.failed.saturating_add(1);
                }
                DispatchOutcome::DeadLettered => {
                    summary.dead_lettered = summary.dead_lettered.saturating_add(1);
                }
            }
        }
        json_response(StatusCode::OK, &summary)
    }

    async fn replay_dead_letter(
        &self,
        dead_letter_id: &str,
        request: ReplayDeadLetterRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let dead_letter_id = DeadLetterId::parse(dead_letter_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid dead_letter_id").with_detail(error.to_string())
        })?;
        let stored_dead_letter = self
            .dead_letters
            .get(dead_letter_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("dead letter does not exist"))?;
        let mut dead_letter = stored_dead_letter.value;
        let message_id = dead_letter.message_id.to_string();
        let stored_message =
            self.message_events.get(&message_id).await?.ok_or_else(|| {
                PlatformError::not_found("message for dead letter does not exist")
            })?;
        let mut message = stored_message.value;
        if message.state != MessageState::DeadLettered {
            return json_response(StatusCode::OK, &message);
        }

        message.state = MessageState::Queued;
        message.attempts = 0;
        message.last_error = None;
        // `None` means "dispatch immediately" and avoids same-tick due-time races in sweeps.
        message.next_attempt_at = None;
        message.updated_at = OffsetDateTime::now_utc();
        self.message_events
            .upsert(&message_id, message.clone(), Some(stored_message.version))
            .await?;

        dead_letter.replay_count = dead_letter.replay_count.saturating_add(1);
        dead_letter.last_replayed_at = Some(OffsetDateTime::now_utc());
        dead_letter.last_replay_reason = Some(
            request
                .reason
                .unwrap_or_else(|| String::from("operator replay")),
        );
        dead_letter
            .metadata
            .touch(sha256_hex(dead_letter.id.as_str().as_bytes()));
        self.dead_letters
            .upsert(
                dead_letter.id.as_str(),
                dead_letter.clone(),
                Some(stored_dead_letter.version),
            )
            .await?;
        self.append_event(
            "mail.message.replayed_from_dead_letter.v1",
            "mail_dead_letter",
            dead_letter.id.as_str(),
            "replayed",
            serde_json::json!({
                "message_id": message.id,
                "replay_count": dead_letter.replay_count,
                "reason": dead_letter.last_replay_reason,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &message)
    }

    async fn dispatch_message_event(
        &self,
        message_id: &str,
        context: &RequestContext,
    ) -> Result<(MessageEventRecord, DispatchOutcome)> {
        let stored = self
            .message_events
            .get(message_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("message event does not exist"))?;
        let mut record = stored.value;
        if record.state == MessageState::Delivered {
            return Ok((record, DispatchOutcome::Delivered));
        }
        if record.state == MessageState::DeadLettered {
            return Ok((record, DispatchOutcome::DeadLettered));
        }
        if let Some(next_attempt_at) = record.next_attempt_at
            && next_attempt_at > OffsetDateTime::now_utc()
        {
            return Err(PlatformError::conflict(
                "message retry is still in backoff window",
            ));
        }

        let reputation = self
            .reputation
            .get(record.domain_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("reputation record does not exist"))?;
        let domain = self
            .domains
            .get(record.domain_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("mail domain record does not exist"))?;
        record.state = MessageState::Delivering;
        record.attempts = record.attempts.saturating_add(1);
        record.updated_at = OffsetDateTime::now_utc();

        let failure_reason = if self
            .mail_quarantine_denial(record.domain_id.as_str(), &domain.value.domain)
            .await?
            .is_some()
        {
            Some(String::from("domain relay suspended by abuse quarantine"))
        } else if reputation.value.suspended {
            Some(String::from("domain relay suspended by reputation policy"))
        } else if record.direction == "outbound" {
            let route = self
                .relay_routes
                .list()
                .await?
                .into_iter()
                .filter(|(_, route)| !route.deleted)
                .map(|(_, route)| route.value)
                .find(|route| route.domain_id == record.domain_id && route.enabled);
            match route {
                Some(route)
                    if route.destination.contains("unreachable")
                        || route.destination.contains("fail") =>
                {
                    Some(String::from("relay destination unavailable"))
                }
                Some(_) => None,
                None => Some(String::from("no active route matched message")),
            }
        } else {
            let route = self
                .inbound_routes
                .list()
                .await?
                .into_iter()
                .filter(|(_, route)| !route.deleted)
                .map(|(_, route)| route.value)
                .find(|route| {
                    route.domain_id == record.domain_id
                        && route.enabled
                        && recipient_matches(&route.recipient_pattern, &record.to)
                });
            match route {
                Some(route)
                    if route.target.contains("unreachable") || route.target.contains("fail") =>
                {
                    Some(String::from("inbound target unavailable"))
                }
                Some(_) => None,
                None => Some(String::from("no active route matched message")),
            }
        };

        if let Some(reason) = failure_reason {
            if reason == "no active route matched message" {
                self.apply_reputation_delta(
                    &record.domain_id,
                    -10,
                    "routing failure reduced domain trust score",
                    context,
                )
                .await?;
            }
            return self
                .record_dispatch_failure(message_id, record, stored.version, &reason, context)
                .await;
        }

        record.state = MessageState::Delivered;
        record.next_attempt_at = None;
        record.last_error = None;
        record.updated_at = OffsetDateTime::now_utc();
        self.message_events
            .upsert(message_id, record.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "mail.message.delivered.v1",
            "message_event",
            message_id,
            "delivered",
            serde_json::json!({
                "attempts": record.attempts,
            }),
            context,
        )
        .await?;
        Ok((record, DispatchOutcome::Delivered))
    }

    async fn mail_quarantine_denial(
        &self,
        domain_id: &str,
        domain_name: &str,
    ) -> Result<Option<String>> {
        let now = OffsetDateTime::now_utc() - Duration::minutes(5);
        let domain_name = domain_name.to_ascii_lowercase();
        let quarantines = self
            .abuse_quarantines
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        for quarantine in quarantines {
            if quarantine.state != "active" || !quarantine.deny_mail_relay {
                continue;
            }
            if quarantine
                .expires_at
                .is_some_and(|expires_at| expires_at <= now)
            {
                continue;
            }
            if quarantine.subject_kind != "mail_domain" {
                continue;
            }
            if quarantine.subject.eq_ignore_ascii_case(&domain_name)
                || quarantine.subject.eq_ignore_ascii_case(domain_id)
            {
                return Ok(Some(format!(
                    "mail domain {} blocked by abuse quarantine",
                    quarantine.subject
                )));
            }
        }
        Ok(None)
    }

    async fn record_dispatch_failure(
        &self,
        message_id: &str,
        mut record: MessageEventRecord,
        expected_version: u64,
        reason: &str,
        context: &RequestContext,
    ) -> Result<(MessageEventRecord, DispatchOutcome)> {
        if record.attempts >= record.max_attempts {
            record.state = MessageState::DeadLettered;
            record.last_error = Some(String::from(reason));
            record.next_attempt_at = None;
            record.updated_at = OffsetDateTime::now_utc();
            self.message_events
                .upsert(message_id, record.clone(), Some(expected_version))
                .await?;
            let dead_letter_id = DeadLetterId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate mail dead letter id")
                    .with_detail(error.to_string())
            })?;
            let dead_letter = MailDeadLetterRecord {
                id: dead_letter_id.clone(),
                message_id: record.id.clone(),
                domain_id: record.domain_id.clone(),
                direction: record.direction.clone(),
                from: record.from.clone(),
                to: record.to.clone(),
                attempts: record.attempts,
                last_error: String::from(reason),
                captured_at: OffsetDateTime::now_utc(),
                replay_count: 0,
                last_replayed_at: None,
                last_replay_reason: None,
                metadata: ResourceMetadata::new(
                    OwnershipScope::Tenant,
                    Some(dead_letter_id.to_string()),
                    sha256_hex(dead_letter_id.as_str().as_bytes()),
                ),
            };
            self.dead_letters
                .create(dead_letter_id.as_str(), dead_letter.clone())
                .await?;
            self.append_event(
                "mail.message.dead_lettered.v1",
                "message_event",
                message_id,
                "dead_lettered",
                serde_json::json!({
                    "reason": reason,
                    "attempts": record.attempts,
                    "dead_letter_id": dead_letter.id,
                }),
                context,
            )
            .await?;
            return Ok((record, DispatchOutcome::DeadLettered));
        }

        let backoff_seconds = compute_backoff_seconds(record.attempts);
        record.state = MessageState::Failed;
        record.last_error = Some(String::from(reason));
        record.next_attempt_at =
            Some(OffsetDateTime::now_utc() + Duration::seconds(backoff_seconds));
        record.updated_at = OffsetDateTime::now_utc();
        self.message_events
            .upsert(message_id, record.clone(), Some(expected_version))
            .await?;
        self.append_event(
            "mail.message.failed.v1",
            "message_event",
            message_id,
            "failed",
            serde_json::json!({
                "reason": reason,
                "attempts": record.attempts,
                "next_attempt_in_seconds": backoff_seconds,
            }),
            context,
        )
        .await?;
        Ok((record, DispatchOutcome::FailedRetryable))
    }

    async fn retry_message(
        &self,
        message_id: &str,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let stored = self
            .message_events
            .get(message_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("message event does not exist"))?;
        let mut record = stored.value;
        if record.state != MessageState::Failed {
            return Err(PlatformError::conflict("message is not in failed state"));
        }
        if let Some(next_attempt_at) = record.next_attempt_at
            && next_attempt_at > OffsetDateTime::now_utc()
        {
            return Err(PlatformError::conflict(
                "message retry is still in backoff window",
            ));
        }
        record.state = MessageState::Queued;
        record.last_error = None;
        record.updated_at = OffsetDateTime::now_utc();
        // `None` means "dispatch immediately" and avoids same-tick due-time races in sweeps.
        record.next_attempt_at = None;
        self.message_events
            .upsert(message_id, record.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "mail.message.requeued.v1",
            "message_event",
            message_id,
            "requeued",
            serde_json::json!({}),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn current_dead_letter(&self, dead_letter_id: &str) -> Result<Response<ApiBody>> {
        let stored = self
            .dead_letters
            .get(dead_letter_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("dead letter does not exist"))?;
        json_response(StatusCode::OK, &stored.value)
    }

    async fn list_auth_records(
        &self,
        query: &BTreeMap<String, String>,
    ) -> Result<Response<ApiBody>> {
        let domain_filter = query
            .get("domain_id")
            .map(|value| {
                MailDomainId::parse(value.clone()).map_err(|error| {
                    PlatformError::invalid("invalid domain_id query parameter")
                        .with_detail(error.to_string())
                })
            })
            .transpose()?;
        let dns_records = self
            .dns_records
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let dns_provider_tasks = self
            .dns_provider_tasks
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let dns_record_delivery_states =
            collect_dns_record_delivery_states(&dns_records, &dns_provider_tasks);
        let relay_routes = self
            .relay_routes
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted && stored.value.enabled)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let inbound_routes = self
            .inbound_routes
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted && stored.value.enabled)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let values = self
            .domains
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|domain| {
                domain_filter
                    .as_ref()
                    .is_none_or(|expected| domain.id.as_str() == expected.as_str())
            })
            .map(|domain| {
                let domain_relay_routes = relay_routes
                    .iter()
                    .filter(|route| route.domain_id == domain.id)
                    .cloned()
                    .collect::<Vec<_>>();
                let domain_inbound_routes = inbound_routes
                    .iter()
                    .filter(|route| route.domain_id == domain.id)
                    .cloned()
                    .collect::<Vec<_>>();
                build_domain_auth_record_view(
                    &domain,
                    &domain_relay_routes,
                    &domain_inbound_routes,
                    &dns_records,
                    &dns_record_delivery_states,
                )
            })
            .collect::<Vec<_>>();
        json_response(StatusCode::OK, &values)
    }

    async fn verify_domain_auth(
        &self,
        domain_id: &str,
        request: VerifyDomainAuthRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let domain_id = MailDomainId::parse(domain_id).map_err(|error| {
            PlatformError::invalid("invalid domain_id in path").with_detail(error.to_string())
        })?;
        let stored_domain = self
            .domains
            .get(domain_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("domain does not exist"))?;
        let mut domain = stored_domain.value;
        let Some(zone_id) = domain.zone_id.clone() else {
            return Err(PlatformError::conflict(
                "domain must have a zone_id to verify DNS auth records",
            ));
        };
        let reconcile_missing = request.reconcile_missing.unwrap_or(false);
        let ttl = request.ttl.unwrap_or(300).max(60);
        let zone = self
            .validate_domain_zone_binding(&zone_id, &domain.domain)
            .await?;
        let zone_id = zone.id.clone();
        if reconcile_missing && !zone.verified {
            return Err(PlatformError::conflict(
                "zone must be verified before reconciling mail auth records",
            ));
        }

        let relay_routes = self
            .relay_routes
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| {
                !stored.deleted && stored.value.enabled && stored.value.domain_id == domain.id
            })
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let inbound_routes = self
            .inbound_routes
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| {
                !stored.deleted && stored.value.enabled && stored.value.domain_id == domain.id
            })
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let mut dns_record_documents = self.dns_records.list().await?;
        let mut dns_records = dns_record_documents
            .iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value.clone())
            .collect::<Vec<_>>();
        let mut dns_provider_tasks = self
            .dns_provider_tasks
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let mut dns_record_delivery_states =
            collect_dns_record_delivery_states(&dns_records, &dns_provider_tasks);
        let mut statuses = compute_domain_dns_status(
            &domain,
            &relay_routes,
            &inbound_routes,
            &dns_records,
            &dns_record_delivery_states,
        );
        let mut reconciled_records = 0_usize;
        let mut stale_records_removed = 0_usize;
        if reconcile_missing {
            for status in statuses.iter().filter(|status| {
                needs_dns_provider_task_reconcile(status, &dns_record_delivery_states)
            }) {
                let record_id = format!(
                    "{}:{}:{}:{}",
                    zone_id,
                    status.name,
                    status.record_type,
                    sha256_hex(status.value.as_bytes())
                );
                let dns_record = DnsRecordHook {
                    id: record_id.clone(),
                    zone_id: zone_id.clone(),
                    name: status.name.clone(),
                    record_type: status.record_type.clone(),
                    value: status.value.clone(),
                    ttl,
                };
                self.dns_records
                    .upsert(&record_id, dns_record.clone(), None)
                    .await?;
                self.enqueue_dns_provider_task("upsert_record", &dns_record)
                    .await?;
                reconciled_records += 1;
            }
            for stale_record in
                collect_stale_mail_dns_records(&domain, &statuses, &dns_record_documents)
            {
                self.dns_records
                    .soft_delete(&stale_record.id, Some(stale_record.version))
                    .await?;
                self.enqueue_dns_provider_task("delete_record", &stale_record.record)
                    .await?;
                stale_records_removed += 1;
            }
            dns_record_documents = self.dns_records.list().await?;
            dns_records = dns_record_documents
                .iter()
                .filter(|(_, stored)| !stored.deleted)
                .map(|(_, stored)| stored.value.clone())
                .collect::<Vec<_>>();
            dns_provider_tasks = self
                .dns_provider_tasks
                .list()
                .await?
                .into_iter()
                .filter(|(_, stored)| !stored.deleted)
                .map(|(_, stored)| stored.value)
                .collect::<Vec<_>>();
            dns_record_delivery_states =
                collect_dns_record_delivery_states(&dns_records, &dns_provider_tasks);
            statuses = compute_domain_dns_status(
                &domain,
                &relay_routes,
                &inbound_routes,
                &dns_records,
                &dns_record_delivery_states,
            );
        }

        let missing_records = statuses.iter().filter(|status| !status.present).count();
        let was_verified = domain.verified;
        let verified = missing_records == 0;
        if was_verified != verified {
            domain.verified = verified;
            domain.metadata.touch(sha256_hex(
                format!(
                    "{}:{}:{}:{}",
                    domain.id.as_str(),
                    domain.domain,
                    domain.verified,
                    missing_records
                )
                .as_bytes(),
            ));
            self.domains
                .upsert(
                    domain.id.as_str(),
                    domain.clone(),
                    Some(stored_domain.version),
                )
                .await?;
        }

        self.append_event(
            "mail.domain.auth_checked.v1",
            "mail_domain",
            domain.id.as_str(),
            "checked",
            serde_json::json!({
                "verified": verified,
                "missing_records": missing_records,
                "reconciled_records": reconciled_records,
                "stale_records_removed": stale_records_removed,
                "zone_id": zone_id,
            }),
            context,
        )
        .await?;
        if reconciled_records > 0 || stale_records_removed > 0 {
            self.append_event(
                "mail.domain.auth_reconciled.v1",
                "mail_domain",
                domain.id.as_str(),
                "reconciled",
                serde_json::json!({
                    "reconciled_records": reconciled_records,
                    "stale_records_removed": stale_records_removed,
                    "ttl": ttl,
                }),
                context,
            )
            .await?;
        }
        if !was_verified && verified {
            self.append_event(
                "mail.domain.verified.v1",
                "mail_domain",
                domain.id.as_str(),
                "verified",
                serde_json::json!({
                    "zone_id": zone_id,
                }),
                context,
            )
            .await?;
        } else if was_verified && !verified {
            self.append_event(
                "mail.domain.unverified.v1",
                "mail_domain",
                domain.id.as_str(),
                "unverified",
                serde_json::json!({
                    "missing_records": missing_records,
                }),
                context,
            )
            .await?;
        }

        let response = VerifyDomainAuthResponse {
            domain_id: domain.id.to_string(),
            domain: domain.domain.clone(),
            zone_id,
            verified,
            reconciled_records,
            stale_records_removed,
            missing_records,
            checked_at: OffsetDateTime::now_utc(),
            records: statuses,
        };
        json_response(StatusCode::OK, &response)
    }

    async fn enqueue_dns_provider_task(&self, action: &str, record: &DnsRecordHook) -> Result<()> {
        let task_id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate DNS provider task id")
                .with_detail(error.to_string())
        })?;
        let task = DnsProviderTaskHook {
            id: task_id.to_string(),
            provider: String::from("cloudflare"),
            action: String::from(action),
            resource_id: record.id.clone(),
            payload: serde_json::json!({
                "zone_id": record.zone_id,
                "name": record.name,
                "record_type": record.record_type,
                "value": record.value,
                "ttl": record.ttl,
            }),
            status: String::from("pending"),
            attempt_count: 0,
            last_attempt_at: None,
            next_attempt_at: None,
            last_error: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let task_key = task.id.clone();
        self.dns_provider_tasks.create(&task_key, task).await?;
        Ok(())
    }

    async fn mail_summary(&self) -> Result<MailSummary> {
        let domains = active_records(self.domains.list().await?);
        let relay_routes = active_records(self.relay_routes.list().await?);
        let inbound_routes = active_records(self.inbound_routes.list().await?);
        let message_events = active_records(self.message_events.list().await?);
        let dead_letters = active_records(self.dead_letters.list().await?);
        let reputation = active_records(self.reputation.list().await?);
        let dns_zones = active_records(self.dns_zones.list().await?);
        let dns_records = active_records(self.dns_records.list().await?);
        let dns_provider_tasks = active_records(self.dns_provider_tasks.list().await?);
        let abuse_quarantines = active_records(self.abuse_quarantines.list().await?);

        let mut message_state_counts = BTreeMap::new();
        for record in &message_events {
            let key = message_state_label(&record.state);
            *message_state_counts.entry(key).or_default() += 1;
        }

        let dead_letter_total_replays = dead_letters
            .iter()
            .map(|record| record.replay_count)
            .sum::<u32>();

        let verified_domain_count = domains.iter().filter(|domain| domain.verified).count();
        let reputation_suspended_count =
            reputation.iter().filter(|record| record.suspended).count();
        let dns_zone_verified_count = dns_zones.iter().filter(|zone| zone.verified).count();
        let abuse_quarantine_denies = abuse_quarantines
            .iter()
            .filter(|record| record.deny_mail_relay)
            .count();

        Ok(MailSummary {
            domain_count: domains.len(),
            verified_domain_count,
            relay_route_count: relay_routes.len(),
            inbound_route_count: inbound_routes.len(),
            message_event_count: message_events.len(),
            message_state_counts,
            dead_letter_count: dead_letters.len(),
            dead_letter_total_replays,
            reputation_record_count: reputation.len(),
            reputation_suspended_count,
            dns_zone_count: dns_zones.len(),
            dns_zone_verified_count,
            dns_record_count: dns_records.len(),
            dns_provider_task_count: dns_provider_tasks.len(),
            abuse_quarantine_count: abuse_quarantines.len(),
            abuse_quarantine_denies,
        })
    }

    async fn adjust_reputation(
        &self,
        domain_id: &str,
        request: AdjustReputationRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        if request.reason.trim().is_empty() {
            return Err(PlatformError::invalid("reason may not be empty"));
        }
        let domain_id = MailDomainId::parse(domain_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid domain_id in path").with_detail(error.to_string())
        })?;
        self.apply_reputation_delta(&domain_id, request.delta, &request.reason, context)
            .await?;
        let stored = self
            .reputation
            .get(domain_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("reputation record does not exist"))?;
        json_response(StatusCode::OK, &stored.value)
    }

    async fn apply_reputation_delta(
        &self,
        domain_id: &MailDomainId,
        delta: i32,
        reason: &str,
        context: &RequestContext,
    ) -> Result<()> {
        let stored = self
            .reputation
            .get(domain_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("reputation record does not exist"))?;
        let mut record = stored.value;
        record.score = (record.score + delta).clamp(-100, 100);
        record.suspended = record.score <= -25;
        record.updated_at = OffsetDateTime::now_utc();
        record.reason = Some(String::from(reason));
        self.reputation
            .upsert(domain_id.as_str(), record.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "mail.reputation.signal.v1",
            "reputation",
            domain_id.as_str(),
            "updated",
            serde_json::json!({
                "delta": delta,
                "score": record.score,
                "suspended": record.suspended,
                "reason": reason,
            }),
            context,
        )
        .await
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
                source_service: String::from("mail"),
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
            .enqueue("mail.events.v1", event, Some(&idempotency))
            .await?;
        Ok(())
    }
}

impl HttpService for MailService {
    fn name(&self) -> &'static str {
        "mail"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/mail")];
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
            let governance_change_request_id =
                extract_change_request_id(request.headers()).map(str::to_owned);
            let segments = path_segments(&path);

            match (method, segments.as_slice()) {
                (Method::GET, ["mail"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                    }),
                )
                .map(Some),
                (Method::GET, ["mail", "summary"]) => {
                    let summary = self.mail_summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["mail", "domains"]) => {
                    let values = self
                        .domains
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["mail", "domains"]) => {
                    let body: CreateDomainRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_domain_authorized(body, &context, Some(change_request_id))
                            .await
                            .map(Some),
                        None => self.create_domain(body, &context).await.map(Some),
                    }
                }
                (Method::GET, ["mail", "auth-records"]) => {
                    let query = parse_query(request.uri().query());
                    self.list_auth_records(&query).await.map(Some)
                }
                (Method::POST, ["mail", "domains", domain_id, "verify-auth"]) => {
                    let body: VerifyDomainAuthRequest = parse_json(request).await?;
                    self.verify_domain_auth(domain_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["mail", "relay-routes"]) => {
                    let values = self
                        .relay_routes
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["mail", "relay-routes"]) => {
                    let body: CreateRelayRouteRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_relay_route_authorized(body, &context, Some(change_request_id))
                            .await
                            .map(Some),
                        None => self.create_relay_route(body, &context).await.map(Some),
                    }
                }
                (Method::GET, ["mail", "inbound-routes"]) => {
                    let values = self
                        .inbound_routes
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["mail", "inbound-routes"]) => {
                    let body: CreateInboundRouteRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_inbound_route_authorized(
                                body,
                                &context,
                                Some(change_request_id),
                            )
                            .await
                            .map(Some),
                        None => self.create_inbound_route(body, &context).await.map(Some),
                    }
                }
                (Method::GET, ["mail", "message-events"]) => {
                    let values = self
                        .message_events
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["mail", "message-events"]) => {
                    let body: CreateMessageEventRequest = parse_json(request).await?;
                    self.create_message_event(body, &context).await.map(Some)
                }
                (Method::POST, ["mail", "message-events", message_id, "dispatch"]) => {
                    self.dispatch_message(message_id, &context).await.map(Some)
                }
                (Method::POST, ["mail", "message-events", message_id, "retry"]) => {
                    self.retry_message(message_id, &context).await.map(Some)
                }
                (Method::POST, ["mail", "dispatch"]) => {
                    let body: DispatchSweepRequest = parse_json(request).await?;
                    self.dispatch_sweep(body, &context).await.map(Some)
                }
                (Method::GET, ["mail", "dead-letters"]) => {
                    let values = self
                        .dead_letters
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["mail", "dead-letters", dead_letter_id]) => {
                    self.current_dead_letter(dead_letter_id).await.map(Some)
                }
                (Method::POST, ["mail", "dead-letters", dead_letter_id, "replay"]) => {
                    let body: ReplayDeadLetterRequest = parse_json(request).await?;
                    self.replay_dead_letter(dead_letter_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["mail", "reputation"]) => {
                    let values = self
                        .reputation
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["mail", "reputation", domain_id, "adjust"]) => {
                    let body: AdjustReputationRequest = parse_json(request).await?;
                    self.adjust_reputation(domain_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["mail", "outbox"]) => {
                    let messages = self.outbox.list_all().await?;
                    json_response(StatusCode::OK, &messages).map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

const MANAGED_MAIL_HOST_SUFFIX: &str = "mail.uhost.example";

#[derive(Debug, Clone)]
struct StaleMailDnsRecord {
    id: String,
    version: u64,
    record: DnsRecordHook,
}

fn build_domain_auth_record_view(
    domain: &MailDomainRecord,
    relay_routes: &[RelayRouteRecord],
    inbound_routes: &[InboundRouteRecord],
    dns_records: &[DnsRecordHook],
    dns_record_delivery_states: &[DnsRecordDeliveryState],
) -> DomainAuthRecordView {
    DomainAuthRecordView {
        domain_id: domain.id.to_string(),
        domain: domain.domain.clone(),
        verified: domain.verified,
        zone_id: domain.zone_id.clone(),
        dns_provider: domain.dns_provider.clone(),
        required_records: compute_domain_dns_status(
            domain,
            relay_routes,
            inbound_routes,
            dns_records,
            dns_record_delivery_states,
        ),
    }
}

fn compute_domain_dns_status(
    domain: &MailDomainRecord,
    relay_routes: &[RelayRouteRecord],
    inbound_routes: &[InboundRouteRecord],
    dns_records: &[DnsRecordHook],
    dns_record_delivery_states: &[DnsRecordDeliveryState],
) -> Vec<DomainAuthRecordStatus> {
    let mut records = expected_domain_dns_records(domain, relay_routes, inbound_routes);
    for record in &mut records {
        let record_id = find_matching_dns_record_id(
            domain.zone_id.as_deref(),
            &record.record_type,
            &record.name,
            &record.value,
            dns_records,
        );
        record.present = record_id.as_deref().is_some_and(|id| {
            latest_dns_record_delivery_state(id, dns_record_delivery_states)
                .is_some_and(|state| state.status.eq_ignore_ascii_case("delivered"))
        });
        record.record_id = record_id;
    }
    records
}

fn collect_dns_record_delivery_states(
    dns_records: &[DnsRecordHook],
    dns_provider_tasks: &[DnsProviderTaskHook],
) -> Vec<DnsRecordDeliveryState> {
    let active_record_ids = dns_records
        .iter()
        .map(|record| record.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut states = dns_provider_tasks
        .iter()
        .filter(|task| {
            task.action == "upsert_record" && active_record_ids.contains(task.resource_id.as_str())
        })
        .map(|task| DnsRecordDeliveryState {
            record_id: task.resource_id.clone(),
            provider_task_id: task.id.clone(),
            provider: task.provider.clone(),
            status: task.status.clone(),
            attempt_count: task.attempt_count,
            last_attempt_at: task.last_attempt_at,
            next_attempt_at: task.next_attempt_at,
            last_error: task.last_error.clone(),
            updated_at: task.updated_at,
        })
        .collect::<Vec<_>>();
    states.sort_by(|left, right| {
        left.record_id
            .cmp(&right.record_id)
            .then_with(|| left.updated_at.cmp(&right.updated_at))
            .then_with(|| left.provider_task_id.cmp(&right.provider_task_id))
    });
    states
}

fn latest_dns_record_delivery_state<'a>(
    record_id: &str,
    dns_record_delivery_states: &'a [DnsRecordDeliveryState],
) -> Option<&'a DnsRecordDeliveryState> {
    dns_record_delivery_states
        .iter()
        .filter(|state| state.record_id == record_id)
        .max_by(|left, right| {
            left.updated_at
                .cmp(&right.updated_at)
                .then_with(|| left.provider_task_id.cmp(&right.provider_task_id))
        })
}

fn needs_dns_provider_task_reconcile(
    status: &DomainAuthRecordStatus,
    dns_record_delivery_states: &[DnsRecordDeliveryState],
) -> bool {
    status
        .record_id
        .as_deref()
        .map(|record_id| {
            latest_dns_record_delivery_state(record_id, dns_record_delivery_states)
                .map(|state| state.status.trim().to_ascii_lowercase())
                .map(|state| !matches!(state.as_str(), "pending" | "retry_pending" | "delivered"))
                .unwrap_or(true)
        })
        .unwrap_or(true)
}

fn collect_stale_mail_dns_records(
    domain: &MailDomainRecord,
    expected_records: &[DomainAuthRecordStatus],
    dns_records: &[(String, StoredDocument<DnsRecordHook>)],
) -> Vec<StaleMailDnsRecord> {
    let Some(zone_id) = domain.zone_id.as_deref() else {
        return Vec::new();
    };
    let expected = expected_records
        .iter()
        .map(|record| dns_record_signature(&record.record_type, &record.name, &record.value))
        .collect::<BTreeSet<_>>();

    dns_records
        .iter()
        .filter_map(|(id, stored)| {
            if stored.deleted || stored.value.zone_id != zone_id {
                return None;
            }
            if !is_managed_mail_dns_record(domain, &stored.value) {
                return None;
            }
            let signature = dns_record_signature(
                &stored.value.record_type,
                &stored.value.name,
                &stored.value.value,
            );
            if expected.contains(&signature) {
                return None;
            }
            Some(StaleMailDnsRecord {
                id: id.clone(),
                version: stored.version,
                record: stored.value.clone(),
            })
        })
        .collect()
}

fn dns_record_signature(record_type: &str, name: &str, value: &str) -> (String, String, String) {
    (
        record_type.trim().to_ascii_uppercase(),
        name.trim().to_ascii_lowercase(),
        String::from(value),
    )
}

fn is_managed_mail_dns_record(domain: &MailDomainRecord, record: &DnsRecordHook) -> bool {
    if record.record_type.eq_ignore_ascii_case("MX")
        && record.name.eq_ignore_ascii_case("@")
        && record.value == format!("10 {}", mail_inbound_host(domain))
    {
        return true;
    }
    if record.record_type.eq_ignore_ascii_case("CNAME")
        && ((record.name.eq_ignore_ascii_case("return-path")
            && record.value == mail_bounce_host(domain))
            || (record.name.eq_ignore_ascii_case("bounce")
                && record.value == mail_outbound_host(domain)))
    {
        return true;
    }
    record.record_type.eq_ignore_ascii_case("TXT")
        && (record.name.starts_with("_uhost.return-path.")
            || record.name.starts_with("_uhost.bounce.")
            || record.name.starts_with("_uhost.inbound-route."))
}

fn expected_domain_dns_records(
    domain: &MailDomainRecord,
    relay_routes: &[RelayRouteRecord],
    inbound_routes: &[InboundRouteRecord],
) -> Vec<DomainAuthRecordStatus> {
    let mut records = expected_domain_auth_records(domain);

    let mut relay_routes = relay_routes
        .iter()
        .filter(|route| route.enabled)
        .cloned()
        .collect::<Vec<_>>();
    relay_routes.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    if !relay_routes.is_empty() {
        records.push(required_dns_record(
            "return_path",
            "CNAME",
            String::from("return-path"),
            mail_bounce_host(domain),
        ));
        records.push(required_dns_record(
            "bounce",
            "CNAME",
            String::from("bounce"),
            mail_outbound_host(domain),
        ));
        for route in relay_routes {
            let route_id = route.id.to_string();
            let route_value = format!(
                "route_id={route_id};destination={};auth_mode={}",
                route.destination, route.auth_mode
            );
            records.push(required_dns_record(
                "return_path",
                "TXT",
                mail_route_evidence_name("return-path", &route_id),
                route_value.clone(),
            ));
            records.push(required_dns_record(
                "bounce",
                "TXT",
                mail_route_evidence_name("bounce", &route_id),
                route_value,
            ));
        }
    }

    let mut inbound_routes = inbound_routes
        .iter()
        .filter(|route| route.enabled)
        .cloned()
        .collect::<Vec<_>>();
    inbound_routes.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    if !inbound_routes.is_empty() {
        records.push(required_dns_record(
            "mx",
            "MX",
            String::from("@"),
            format!("10 {}", mail_inbound_host(domain)),
        ));
        for route in inbound_routes {
            let route_id = route.id.to_string();
            let route_value = format!(
                "route_id={route_id};recipient_pattern={};target={}",
                route.recipient_pattern, route.target
            );
            records.push(required_dns_record(
                "inbound_route",
                "TXT",
                mail_route_evidence_name("inbound-route", &route_id),
                route_value,
            ));
        }
    }

    records
}

fn expected_domain_auth_records(domain: &MailDomainRecord) -> Vec<DomainAuthRecordStatus> {
    let dkim_value = format!(
        "v=DKIM1; k=rsa; p={}",
        sha256_hex(domain.dkim_selector.as_bytes())
    );
    vec![
        required_dns_record(
            "auth_dkim",
            "TXT",
            format!("{}._domainkey", domain.dkim_selector),
            dkim_value,
        ),
        required_dns_record(
            "auth_spf",
            "TXT",
            String::from("@"),
            domain.spf_value.clone(),
        ),
        required_dns_record(
            "auth_dmarc",
            "TXT",
            String::from("_dmarc"),
            domain.dmarc_value.clone(),
        ),
    ]
}

fn required_dns_record(
    purpose: &str,
    record_type: &str,
    name: String,
    value: String,
) -> DomainAuthRecordStatus {
    DomainAuthRecordStatus {
        purpose: String::from(purpose),
        record_type: String::from(record_type),
        name,
        value,
        present: false,
        record_id: None,
    }
}

fn mail_inbound_host(domain: &MailDomainRecord) -> String {
    managed_mail_host(domain, "inbound")
}

fn mail_outbound_host(domain: &MailDomainRecord) -> String {
    managed_mail_host(domain, "outbound")
}

fn mail_bounce_host(domain: &MailDomainRecord) -> String {
    managed_mail_host(domain, "bounce")
}

fn managed_mail_host(domain: &MailDomainRecord, role: &str) -> String {
    format!("{role}.{}.{}", domain.id.as_str(), MANAGED_MAIL_HOST_SUFFIX)
}

fn mail_route_evidence_name(kind: &str, route_id: &str) -> String {
    format!("_uhost.{kind}.{route_id}")
}

fn find_matching_dns_record_id(
    zone_id: Option<&str>,
    record_type: &str,
    name: &str,
    value: &str,
    dns_records: &[DnsRecordHook],
) -> Option<String> {
    let zone_id = zone_id?;
    dns_records
        .iter()
        .find(|record| {
            record.zone_id == zone_id
                && record.record_type.eq_ignore_ascii_case(record_type)
                && record.name.eq_ignore_ascii_case(name)
                && record.value == value
        })
        .map(|record| record.id.clone())
}

fn normalize_direction(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "outbound" | "inbound" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "direction must be `outbound` or `inbound`",
        )),
    }
}

fn recipient_matches(pattern: &str, recipient: &str) -> bool {
    let pattern = pattern.trim();
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return recipient
            .trim()
            .to_ascii_lowercase()
            .starts_with(&prefix.to_ascii_lowercase());
    }
    recipient.trim().eq_ignore_ascii_case(pattern)
}

fn normalize_optional_zone_id(value: Option<String>) -> Result<Option<String>> {
    match value {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            let zone_id = ZoneId::parse(trimmed.to_owned()).map_err(|error| {
                PlatformError::invalid("invalid zone_id").with_detail(error.to_string())
            })?;
            Ok(Some(zone_id.to_string()))
        }
        None => Ok(None),
    }
}

fn trimmed_nonempty(value: String, field: &'static str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty")));
    }
    Ok(value.to_owned())
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

fn mail_domain_mutation_digest(
    record: &MailDomainRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "domain": record.domain,
        "zone_id": record.zone_id,
        "dns_provider": record.dns_provider,
        "dkim_selector": record.dkim_selector,
        "spf_value": record.spf_value,
        "dmarc_value": record.dmarc_value,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode mail domain mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn relay_route_mutation_digest(
    record: &RelayRouteRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "domain_id": record.domain_id,
        "destination": record.destination,
        "auth_mode": record.auth_mode,
        "enabled": record.enabled,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode relay-route mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn inbound_route_mutation_digest(
    record: &InboundRouteRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "domain_id": record.domain_id,
        "recipient_pattern": record.recipient_pattern,
        "target": record.target,
        "enabled": record.enabled,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode inbound-route mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn default_message_max_attempts() -> u32 {
    5
}

fn compute_backoff_seconds(attempts: u32) -> i64 {
    let exponent = attempts.saturating_sub(1).min(10);
    let multiplier = 1_u32 << exponent;
    i64::from((30_u32.saturating_mul(multiplier)).clamp(30, 3600))
}

fn default_true() -> bool {
    true
}

fn active_records<T>(records: Vec<(String, StoredDocument<T>)>) -> Vec<T> {
    records
        .into_iter()
        .filter(|(_, stored)| !stored.deleted)
        .map(|(_, stored)| stored.value)
        .collect()
}

fn message_state_label(state: &MessageState) -> String {
    match state {
        MessageState::Queued => String::from("queued"),
        MessageState::Delivering => String::from("delivering"),
        MessageState::Delivered => String::from("delivered"),
        MessageState::Failed => String::from("failed"),
        MessageState::DeadLettered => String::from("dead_lettered"),
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tempfile::tempdir;
    use time::{Duration, OffsetDateTime};

    use super::{
        AbuseQuarantineHookRecord, CreateDomainRequest, CreateInboundRouteRequest,
        CreateMessageEventRequest, CreateRelayRouteRequest, DispatchSummary, DispatchSweepRequest,
        DnsProviderTaskHook, DnsRecordHook, DnsZoneHook, GovernanceChangeRequestMirror,
        MailDeadLetterRecord, MailService, MessageEventRecord, MessageState,
        ReplayDeadLetterRequest, VerifyDomainAuthRequest,
    };
    use uhost_core::{ErrorCode, RequestContext, sha256_hex};
    use uhost_types::{AuditId, ChangeRequestId, DeadLetterId, OwnershipScope, ResourceMetadata};

    async fn seed_dns_zone(service: &MailService, zone_id: &str, domain: &str, verified: bool) {
        service
            .dns_zones
            .create(
                zone_id,
                DnsZoneHook {
                    id: String::from(zone_id),
                    domain: String::from(domain),
                    verified,
                    metadata: ResourceMetadata::new(
                        OwnershipScope::Tenant,
                        Some(String::from(zone_id)),
                        sha256_hex(zone_id.as_bytes()),
                    ),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }

    async fn seed_governance_change_request(service: &MailService, state: &str) -> String {
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

    async fn new_metadata(id: &str) -> ResourceMetadata {
        ResourceMetadata::new(
            OwnershipScope::Tenant,
            Some(id.to_owned()),
            sha256_hex(id.as_bytes()),
        )
    }

    async fn mark_provider_tasks_delivered(service: &MailService, action: &str) {
        for (task_id, stored_task) in service
            .dns_provider_tasks
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
        {
            if stored_task.deleted || stored_task.value.action != action {
                continue;
            }
            let mut task = stored_task.value;
            task.attempt_count = task.attempt_count.saturating_add(1);
            task.last_attempt_at = Some(OffsetDateTime::now_utc());
            task.next_attempt_at = None;
            task.status = String::from("delivered");
            task.last_error = None;
            task.updated_at = OffsetDateTime::now_utc();
            service
                .dns_provider_tasks
                .upsert(&task_id, task, Some(stored_task.version))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }
    }

    #[tokio::test]
    async fn outbound_dispatch_fails_without_route() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created_domain = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("example.com"),
                    zone_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created_domain.status(), http::StatusCode::CREATED);
        let domains = service
            .domains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domain_id = domains[0].1.value.id.to_string();

        let created_message = service
            .create_message_event(
                CreateMessageEventRequest {
                    domain_id,
                    direction: String::from("outbound"),
                    from: String::from("alerts@example.com"),
                    to: String::from("ops@example.net"),
                    subject: String::from("Alert"),
                    max_attempts: None,
                    deliver_after_seconds: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created_message.status(), http::StatusCode::CREATED);

        let messages = service
            .message_events
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let message_id = messages[0].1.value.id.to_string();
        let dispatched = service
            .dispatch_message(&message_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(dispatched.status(), http::StatusCode::OK);
        let current = service
            .message_events
            .get(&message_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing message"));
        assert_eq!(current.value.state, super::MessageState::Failed);
    }

    #[tokio::test]
    async fn outbound_dispatch_succeeds_with_route() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        seed_dns_zone(&service, "dns_demo", "example.org", true).await;

        let _ = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("example.org"),
                    zone_id: Some(String::from("dns_demo")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domains = service
            .domains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domain_id = domains[0].1.value.id.to_string();
        let _ = service
            .create_relay_route(
                CreateRelayRouteRequest {
                    domain_id: domain_id.clone(),
                    destination: String::from("smtp.relay.local:587"),
                    auth_mode: String::from("mtls"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_message_event(
                CreateMessageEventRequest {
                    domain_id,
                    direction: String::from("outbound"),
                    from: String::from("alerts@example.org"),
                    to: String::from("ops@example.net"),
                    subject: String::from("Delivery"),
                    max_attempts: None,
                    deliver_after_seconds: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let messages = service
            .message_events
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let message_id = messages[0].1.value.id.to_string();
        let response = service
            .dispatch_message(&message_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::OK);
        let current = service
            .message_events
            .get(&message_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing message"));
        assert_eq!(current.value.state, super::MessageState::Delivered);
    }

    #[tokio::test]
    async fn create_domain_persists_change_authorization_when_governed() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("mail.operator");
        let change_request_id = seed_governance_change_request(&service, "approved").await;

        let response = service
            .create_domain_authorized(
                CreateDomainRequest {
                    domain: String::from("governed-mail.example"),
                    zone_id: None,
                },
                &context,
                Some(change_request_id.as_str()),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let domain: super::MailDomainRecord =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));

        let authorization = domain
            .change_authorization
            .as_ref()
            .unwrap_or_else(|| panic!("missing mail domain change authorization"));
        assert_eq!(
            authorization.change_request_id.as_str(),
            change_request_id.as_str()
        );
        assert_eq!(authorization.mutation_digest.len(), 64);
        assert_eq!(
            domain
                .metadata
                .annotations
                .get("governance.change_request_id")
                .map(String::as_str),
            Some(change_request_id.as_str())
        );
        assert_eq!(
            domain
                .metadata
                .annotations
                .get("mail.mutation_digest")
                .map(String::len),
            Some(64)
        );
    }

    #[tokio::test]
    async fn create_domain_rejects_mismatched_zone_binding() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        seed_dns_zone(&service, "dns_zoneother", "other.example", true).await;

        let error = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("victim.example"),
                    zone_id: Some(String::from("dns_zoneother")),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected mismatched zone rejection"));
        assert_eq!(error.code, ErrorCode::Forbidden);
    }

    #[tokio::test]
    async fn create_domain_rejects_invalid_zone_identifier_shape() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("victim.example"),
                    zone_id: Some(String::from("dns_zone_demo")),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected invalid zone_id rejection"));
        assert_eq!(error.code, ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn inbound_prefix_routes_match_case_insensitively_and_trim_whitespace() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("inbound.example"),
                    zone_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domains = service
            .domains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domain_id = domains[0].1.value.id.to_string();
        let _ = service
            .create_inbound_route(
                CreateInboundRouteRequest {
                    domain_id: domain_id.clone(),
                    recipient_pattern: String::from("  Support@*  "),
                    target: String::from("smtp.inbound.local:2525"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_message_event(
                CreateMessageEventRequest {
                    domain_id,
                    direction: String::from("inbound"),
                    from: String::from("sender@example.net"),
                    to: String::from("  SUPPORT@example.org  "),
                    subject: String::from("Case insensitive routing"),
                    max_attempts: None,
                    deliver_after_seconds: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let messages = service
            .message_events
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let message_id = messages[0].1.value.id.to_string();
        let response = service
            .dispatch_message(&message_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::OK);
        let current = service
            .message_events
            .get(&message_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing message"));
        assert_eq!(current.value.state, super::MessageState::Delivered);
        assert_eq!(current.value.to, "SUPPORT@example.org");
    }

    #[tokio::test]
    async fn message_moves_to_dead_letter_after_retry_budget_is_exhausted() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("example.net"),
                    zone_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domains = service
            .domains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domain_id = domains[0].1.value.id.to_string();

        let _ = service
            .create_message_event(
                CreateMessageEventRequest {
                    domain_id,
                    direction: String::from("outbound"),
                    from: String::from("alerts@example.net"),
                    to: String::from("ops@example.net"),
                    subject: String::from("Critical"),
                    max_attempts: Some(1),
                    deliver_after_seconds: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let messages = service
            .message_events
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let message_id = messages[0].1.value.id.to_string();
        let _ = service
            .dispatch_message(&message_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let current = service
            .message_events
            .get(&message_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing message"));
        assert_eq!(current.value.state, super::MessageState::DeadLettered);
        let dead_letters = service
            .dead_letters
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(dead_letters.len(), 1);
    }

    #[tokio::test]
    async fn dead_letter_replay_requeues_message() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("example.edu"),
                    zone_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domains = service
            .domains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domain_id = domains[0].1.value.id.to_string();
        let _ = service
            .create_message_event(
                CreateMessageEventRequest {
                    domain_id,
                    direction: String::from("outbound"),
                    from: String::from("alerts@example.edu"),
                    to: String::from("ops@example.net"),
                    subject: String::from("Replay"),
                    max_attempts: Some(1),
                    deliver_after_seconds: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let messages = service
            .message_events
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let message_id = messages[0].1.value.id.to_string();
        let _ = service
            .dispatch_message(&message_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let dead_letters = service
            .dead_letters
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let dead_letter_id = dead_letters[0].1.value.id.to_string();

        let response = service
            .replay_dead_letter(
                &dead_letter_id,
                ReplayDeadLetterRequest {
                    reason: Some(String::from("manual replay")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::OK);
        let message = service
            .message_events
            .get(&message_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing message"));
        assert_eq!(message.value.state, super::MessageState::Queued);
        let dead_letter = service
            .dead_letters
            .get(&dead_letter_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing dead letter"));
        assert_eq!(dead_letter.value.replay_count, 1);
    }

    #[tokio::test]
    async fn dispatch_sweep_reports_delivery_summary() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("example.io"),
                    zone_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domains = service
            .domains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domain_id = domains[0].1.value.id.to_string();
        let _ = service
            .create_relay_route(
                CreateRelayRouteRequest {
                    domain_id: domain_id.clone(),
                    destination: String::from("smtp.relay.local:587"),
                    auth_mode: String::from("mtls"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_message_event(
                CreateMessageEventRequest {
                    domain_id: domain_id.clone(),
                    direction: String::from("outbound"),
                    from: String::from("alerts@example.io"),
                    to: String::from("ops@example.net"),
                    subject: String::from("Sweep"),
                    max_attempts: None,
                    deliver_after_seconds: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_message_event(
                CreateMessageEventRequest {
                    domain_id,
                    direction: String::from("inbound"),
                    from: String::from("alerts@example.io"),
                    to: String::from("nobody@example.net"),
                    subject: String::from("Dead Letter"),
                    max_attempts: Some(1),
                    deliver_after_seconds: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let sweep = service
            .dispatch_sweep(DispatchSweepRequest { limit: Some(10) }, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(sweep.status(), http::StatusCode::OK);
        let body = sweep
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let payload: DispatchSummary =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(payload.inspected, 2);
        assert_eq!(payload.delivered, 1);
        assert_eq!(payload.dead_lettered, 1);
        assert_eq!(payload.skipped_not_due, 0);
        let dead_letters = service
            .dead_letters
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(dead_letters.len(), 1);
    }

    #[tokio::test]
    async fn verify_auth_without_reconcile_reports_missing_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        seed_dns_zone(&service, "dns_zonedemo", "auth-missing.example", true).await;

        let _ = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("auth-missing.example"),
                    zone_id: Some(String::from("dns_zonedemo")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domains = service
            .domains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domain_id = domains[0].1.value.id.to_string();

        let response = service
            .verify_domain_auth(
                &domain_id,
                VerifyDomainAuthRequest {
                    reconcile_missing: Some(false),
                    ttl: None,
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
        assert!(!payload["verified"].as_bool().unwrap_or(true));
        assert_eq!(payload["missing_records"].as_u64().unwrap_or_default(), 3);
        assert_eq!(
            payload["reconciled_records"].as_u64().unwrap_or_default(),
            0
        );
    }

    #[tokio::test]
    async fn verify_auth_reconcile_requires_verified_zone() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        seed_dns_zone(&service, "dns_zonedemo", "auth-ready.example", false).await;

        let _ = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("auth-ready.example"),
                    zone_id: Some(String::from("dns_zonedemo")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domains = service
            .domains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domain_id = domains[0].1.value.id.to_string();

        let error = service
            .verify_domain_auth(
                &domain_id,
                VerifyDomainAuthRequest {
                    reconcile_missing: Some(true),
                    ttl: Some(120),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected unverified-zone rejection"));
        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(
            service
                .dns_records
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_empty()
        );
        assert!(
            service
                .dns_provider_tasks
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_empty()
        );
    }

    #[tokio::test]
    async fn verify_auth_reconcile_rejects_invalid_stored_zone_identifier() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("tampered.example"),
                    zone_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domain_id = service
            .domains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .id
            .to_string();
        let stored_domain = service
            .domains
            .get(&domain_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing domain"));
        let mut tampered_domain = stored_domain.value;
        tampered_domain.zone_id = Some(String::from("dns_zone_demo"));
        service
            .domains
            .upsert(&domain_id, tampered_domain, Some(stored_domain.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .verify_domain_auth(
                &domain_id,
                VerifyDomainAuthRequest {
                    reconcile_missing: Some(true),
                    ttl: Some(120),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected invalid stored zone_id rejection"));
        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert!(
            service
                .dns_records
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_empty()
        );
        assert!(
            service
                .dns_provider_tasks
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_empty()
        );
    }

    #[tokio::test]
    async fn verify_auth_reconcile_requires_delivered_provider_task_evidence() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        seed_dns_zone(&service, "dns_zonedemo", "auth-ready.example", true).await;

        let _ = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("auth-ready.example"),
                    zone_id: Some(String::from("dns_zonedemo")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domains = service
            .domains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domain_id = domains[0].1.value.id.to_string();

        let response = service
            .verify_domain_auth(
                &domain_id,
                VerifyDomainAuthRequest {
                    reconcile_missing: Some(true),
                    ttl: Some(120),
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
        assert!(!payload["verified"].as_bool().unwrap_or(true));
        assert_eq!(payload["missing_records"].as_u64().unwrap_or_default(), 3);
        assert_eq!(
            payload["reconciled_records"].as_u64().unwrap_or_default(),
            3
        );
        let records = payload["records"]
            .as_array()
            .unwrap_or_else(|| panic!("records should be an array"));
        assert_eq!(records.len(), 3);
        assert!(records.iter().all(|entry| {
            !entry
                .get("present")
                .and_then(Value::as_bool)
                .unwrap_or(true)
        }));

        let dns_records = service
            .dns_records
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(dns_records.len(), 3);
        let provider_tasks = service
            .dns_provider_tasks
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(provider_tasks.len(), 3);
        let repeated_response = service
            .verify_domain_auth(
                &domain_id,
                VerifyDomainAuthRequest {
                    reconcile_missing: Some(true),
                    ttl: Some(120),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let repeated_body = repeated_response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let repeated_payload: Value =
            serde_json::from_slice(&repeated_body).unwrap_or_else(|error| panic!("{error}"));
        assert!(!repeated_payload["verified"].as_bool().unwrap_or(true));
        assert_eq!(
            repeated_payload["reconciled_records"]
                .as_u64()
                .unwrap_or(99),
            0
        );
        assert_eq!(
            service
                .dns_provider_tasks
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            3
        );
        let pending_domain = service
            .domains
            .get(&domain_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("domain missing after auth verify"));
        assert!(!pending_domain.value.verified);

        for (task_id, stored_task) in provider_tasks {
            let mut task = stored_task.value;
            task.status = String::from("delivered");
            task.last_error = None;
            task.updated_at = OffsetDateTime::now_utc();
            service
                .dns_provider_tasks
                .upsert(&task_id, task, Some(stored_task.version))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let delivered_response = service
            .verify_domain_auth(
                &domain_id,
                VerifyDomainAuthRequest {
                    reconcile_missing: Some(false),
                    ttl: Some(120),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let delivered_body = delivered_response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let delivered_payload: Value =
            serde_json::from_slice(&delivered_body).unwrap_or_else(|error| panic!("{error}"));
        assert!(delivered_payload["verified"].as_bool().unwrap_or(false));
        assert_eq!(
            delivered_payload["missing_records"].as_u64().unwrap_or(99),
            0
        );
        assert_eq!(
            delivered_payload["reconciled_records"]
                .as_u64()
                .unwrap_or(99),
            0
        );
        let updated_domain = service
            .domains
            .get(&domain_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("domain missing after delivered auth verify"));
        assert!(updated_domain.value.verified);
    }

    #[tokio::test]
    async fn verify_auth_reconcile_uses_delivery_state_to_retry_only_failed_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        seed_dns_zone(&service, "dns_zonedemo", "delivery-state.example", true).await;

        let _ = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("delivery-state.example"),
                    zone_id: Some(String::from("dns_zonedemo")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domains = service
            .domains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domain_id = domains[0].1.value.id.to_string();

        let initial_response = service
            .verify_domain_auth(
                &domain_id,
                VerifyDomainAuthRequest {
                    reconcile_missing: Some(true),
                    ttl: Some(120),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let initial_payload: Value = serde_json::from_slice(
            &initial_response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            initial_payload["reconciled_records"]
                .as_u64()
                .unwrap_or_default(),
            3
        );

        let mut provider_tasks = service
            .dns_provider_tasks
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        provider_tasks
            .sort_by(|left, right| left.1.value.resource_id.cmp(&right.1.value.resource_id));
        assert_eq!(provider_tasks.len(), 3);

        let delivered_record_id = provider_tasks[0].1.value.resource_id.clone();
        let retry_pending_record_id = provider_tasks[1].1.value.resource_id.clone();
        let failed_record_id = provider_tasks[2].1.value.resource_id.clone();
        let now = OffsetDateTime::now_utc() - Duration::minutes(5);

        for (index, (task_id, stored_task)) in provider_tasks.into_iter().enumerate() {
            let mut task = stored_task.value;
            task.attempt_count = 1;
            task.last_attempt_at = Some(now + Duration::seconds(index as i64));
            task.updated_at = now + Duration::seconds(index as i64);
            match index {
                0 => {
                    task.status = String::from("delivered");
                    task.next_attempt_at = None;
                    task.last_error = None;
                }
                1 => {
                    task.status = String::from("retry_pending");
                    task.next_attempt_at = Some(now + Duration::seconds(300));
                    task.last_error = Some(String::from("provider rate limited"));
                }
                2 => {
                    task.status = String::from("failed");
                    task.next_attempt_at = None;
                    task.last_error = Some(String::from("provider validation rejected alias"));
                }
                _ => unreachable!("unexpected provider task count"),
            }
            service
                .dns_provider_tasks
                .upsert(&task_id, task, Some(stored_task.version))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let check_response = service
            .verify_domain_auth(
                &domain_id,
                VerifyDomainAuthRequest {
                    reconcile_missing: Some(false),
                    ttl: Some(120),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let check_payload: Value = serde_json::from_slice(
            &check_response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!check_payload["verified"].as_bool().unwrap_or(true));
        assert_eq!(check_payload["missing_records"].as_u64().unwrap_or(99), 2);
        let present_count = check_payload["records"]
            .as_array()
            .unwrap_or_else(|| panic!("records should be an array"))
            .iter()
            .filter(|entry| entry["present"].as_bool() == Some(true))
            .count();
        assert_eq!(present_count, 1);

        let retry_response = service
            .verify_domain_auth(
                &domain_id,
                VerifyDomainAuthRequest {
                    reconcile_missing: Some(true),
                    ttl: Some(120),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let retry_payload: Value = serde_json::from_slice(
            &retry_response
                .into_body()
                .collect()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!retry_payload["verified"].as_bool().unwrap_or(true));
        assert_eq!(
            retry_payload["reconciled_records"]
                .as_u64()
                .unwrap_or_default(),
            1
        );
        assert_eq!(retry_payload["missing_records"].as_u64().unwrap_or(99), 2);

        let dns_records = service
            .dns_records
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let provider_tasks = service
            .dns_provider_tasks
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        assert_eq!(provider_tasks.len(), 4);

        let mut tasks_by_record = std::collections::BTreeMap::<String, usize>::new();
        for task in &provider_tasks {
            *tasks_by_record.entry(task.resource_id.clone()).or_default() += 1;
        }
        assert_eq!(tasks_by_record.get(&delivered_record_id), Some(&1));
        assert_eq!(tasks_by_record.get(&retry_pending_record_id), Some(&1));
        assert_eq!(tasks_by_record.get(&failed_record_id), Some(&2));

        let delivery_states =
            super::collect_dns_record_delivery_states(&dns_records, &provider_tasks);
        let delivered_state =
            super::latest_dns_record_delivery_state(&delivered_record_id, &delivery_states)
                .unwrap_or_else(|| panic!("missing delivered delivery state"));
        assert_eq!(delivered_state.status, "delivered");
        let retry_pending_state =
            super::latest_dns_record_delivery_state(&retry_pending_record_id, &delivery_states)
                .unwrap_or_else(|| panic!("missing retry-pending delivery state"));
        assert_eq!(retry_pending_state.status, "retry_pending");
        let failed_retry_state =
            super::latest_dns_record_delivery_state(&failed_record_id, &delivery_states)
                .unwrap_or_else(|| panic!("missing failed retry delivery state"));
        assert_eq!(failed_retry_state.status, "pending");
        assert_eq!(failed_retry_state.attempt_count, 0);
    }

    #[tokio::test]
    async fn verify_auth_reconciles_mail_routing_dns_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        seed_dns_zone(&service, "dns_zoneroutes", "routing.example", true).await;

        let _ = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("routing.example"),
                    zone_id: Some(String::from("dns_zoneroutes")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domain = service
            .domains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .clone();
        let domain_id = domain.id.to_string();

        let _ = service
            .create_relay_route(
                CreateRelayRouteRequest {
                    domain_id: domain_id.clone(),
                    destination: String::from("smtp.routing.local:587"),
                    auth_mode: String::from("mtls"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_inbound_route(
                CreateInboundRouteRequest {
                    domain_id: domain_id.clone(),
                    recipient_pattern: String::from("*"),
                    target: String::from("hook://routing"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .verify_domain_auth(
                &domain_id,
                VerifyDomainAuthRequest {
                    reconcile_missing: Some(true),
                    ttl: Some(120),
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
        assert!(!payload["verified"].as_bool().unwrap_or(true));
        assert_eq!(payload["missing_records"].as_u64().unwrap_or(99), 9);
        assert_eq!(
            payload["reconciled_records"].as_u64().unwrap_or_default(),
            9
        );
        assert_eq!(
            payload["stale_records_removed"]
                .as_u64()
                .unwrap_or_default(),
            0
        );

        let records = payload["records"]
            .as_array()
            .unwrap_or_else(|| panic!("records should be an array"));
        assert_eq!(records.len(), 9);
        assert!(records.iter().any(|entry| {
            entry["purpose"].as_str() == Some("mx")
                && entry["record_type"].as_str() == Some("MX")
                && entry["name"].as_str() == Some("@")
        }));
        assert!(records.iter().any(|entry| {
            entry["purpose"].as_str() == Some("return_path")
                && entry["record_type"].as_str() == Some("CNAME")
                && entry["name"].as_str() == Some("return-path")
        }));
        assert!(records.iter().any(|entry| {
            entry["purpose"].as_str() == Some("bounce")
                && entry["record_type"].as_str() == Some("CNAME")
                && entry["name"].as_str() == Some("bounce")
        }));
        assert!(records.iter().any(|entry| {
            entry["purpose"].as_str() == Some("inbound_route")
                && entry["record_type"].as_str() == Some("TXT")
                && entry["name"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("_uhost.inbound-route.")
        }));

        let active_dns_records = service
            .dns_records
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        assert_eq!(active_dns_records.len(), 9);
        assert!(active_dns_records.iter().any(|record| {
            record.record_type == "MX"
                && record.name == "@"
                && record.value == format!("10 {}", super::mail_inbound_host(&domain))
        }));
        assert!(active_dns_records.iter().any(|record| {
            record.record_type == "CNAME"
                && record.name == "return-path"
                && record.value == super::mail_bounce_host(&domain)
        }));
        assert!(active_dns_records.iter().any(|record| {
            record.record_type == "CNAME"
                && record.name == "bounce"
                && record.value == super::mail_outbound_host(&domain)
        }));

        mark_provider_tasks_delivered(&service, "upsert_record").await;

        let delivered_response = service
            .verify_domain_auth(
                &domain_id,
                VerifyDomainAuthRequest {
                    reconcile_missing: Some(false),
                    ttl: Some(120),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let delivered_body = delivered_response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let delivered_payload: Value =
            serde_json::from_slice(&delivered_body).unwrap_or_else(|error| panic!("{error}"));
        assert!(delivered_payload["verified"].as_bool().unwrap_or(false));
        assert_eq!(
            delivered_payload["missing_records"].as_u64().unwrap_or(99),
            0
        );
        assert_eq!(
            delivered_payload["reconciled_records"]
                .as_u64()
                .unwrap_or(99),
            0
        );
        assert_eq!(
            delivered_payload["stale_records_removed"]
                .as_u64()
                .unwrap_or(99),
            0
        );
    }

    #[tokio::test]
    async fn verify_auth_reconcile_cleans_stale_mail_routing_dns_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        seed_dns_zone(&service, "dns_zonecleanup", "cleanup.example", true).await;

        let _ = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("cleanup.example"),
                    zone_id: Some(String::from("dns_zonecleanup")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domain = service
            .domains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .clone();
        let domain_id = domain.id.to_string();

        let stale_records = [
            DnsRecordHook {
                id: String::from("stale-mx"),
                zone_id: String::from("dns_zonecleanup"),
                name: String::from("@"),
                record_type: String::from("MX"),
                value: format!("10 {}", super::mail_inbound_host(&domain)),
                ttl: 60,
            },
            DnsRecordHook {
                id: String::from("stale-return-path"),
                zone_id: String::from("dns_zonecleanup"),
                name: String::from("return-path"),
                record_type: String::from("CNAME"),
                value: super::mail_bounce_host(&domain),
                ttl: 60,
            },
            DnsRecordHook {
                id: String::from("stale-bounce"),
                zone_id: String::from("dns_zonecleanup"),
                name: String::from("bounce"),
                record_type: String::from("CNAME"),
                value: super::mail_outbound_host(&domain),
                ttl: 60,
            },
            DnsRecordHook {
                id: String::from("stale-return-path-evidence"),
                zone_id: String::from("dns_zonecleanup"),
                name: String::from("_uhost.return-path.route_stale"),
                record_type: String::from("TXT"),
                value: String::from(
                    "route_id=route_stale;destination=smtp.old.local:25;auth_mode=mtls",
                ),
                ttl: 60,
            },
            DnsRecordHook {
                id: String::from("stale-inbound-route-evidence"),
                zone_id: String::from("dns_zonecleanup"),
                name: String::from("_uhost.inbound-route.route_stale"),
                record_type: String::from("TXT"),
                value: String::from("route_id=route_stale;recipient_pattern=*;target=hook://old"),
                ttl: 60,
            },
        ];
        for record in stale_records {
            let record_id = record.id.clone();
            service
                .dns_records
                .create(record_id.as_str(), record)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let response = service
            .verify_domain_auth(
                &domain_id,
                VerifyDomainAuthRequest {
                    reconcile_missing: Some(true),
                    ttl: Some(120),
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
        assert!(!payload["verified"].as_bool().unwrap_or(true));
        assert_eq!(payload["missing_records"].as_u64().unwrap_or(99), 3);
        assert_eq!(
            payload["reconciled_records"].as_u64().unwrap_or_default(),
            3
        );
        assert_eq!(
            payload["stale_records_removed"]
                .as_u64()
                .unwrap_or_default(),
            5
        );

        let dns_records = service
            .dns_records
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let active_dns_records = dns_records
            .iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value.clone())
            .collect::<Vec<_>>();
        assert_eq!(active_dns_records.len(), 3);
        for stale_id in [
            "stale-mx",
            "stale-return-path",
            "stale-bounce",
            "stale-return-path-evidence",
            "stale-inbound-route-evidence",
        ] {
            let stored = dns_records
                .iter()
                .find(|(id, _)| id == stale_id)
                .map(|(_, stored)| stored)
                .unwrap_or_else(|| panic!("missing stale record {stale_id}"));
            assert!(stored.deleted);
        }

        let provider_tasks = service
            .dns_provider_tasks
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let upsert_tasks = provider_tasks
            .iter()
            .filter(|task| task.action == "upsert_record")
            .count();
        let delete_tasks = provider_tasks
            .iter()
            .filter(|task| task.action == "delete_record")
            .count();
        assert_eq!(upsert_tasks, 3);
        assert_eq!(delete_tasks, 5);
    }

    #[tokio::test]
    async fn abuse_quarantine_blocks_mail_delivery_until_released() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("blocked.example"),
                    zone_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domains = service
            .domains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domain_id = domains[0].1.value.id.to_string();
        let _ = service
            .create_relay_route(
                CreateRelayRouteRequest {
                    domain_id: domain_id.clone(),
                    destination: String::from("smtp.relay.local:587"),
                    auth_mode: String::from("mtls"),
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
                    subject_kind: String::from("mail_domain"),
                    subject: String::from("blocked.example"),
                    state: String::from("active"),
                    deny_mail_relay: true,
                    expires_at: None,
                    released_at: None,
                    released_reason: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_message_event(
                CreateMessageEventRequest {
                    domain_id: domain_id.clone(),
                    direction: String::from("outbound"),
                    from: String::from("alerts@blocked.example"),
                    to: String::from("ops@example.net"),
                    subject: String::from("blocked"),
                    max_attempts: Some(1),
                    deliver_after_seconds: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let messages = service
            .message_events
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let message_id = messages[0].1.value.id.to_string();
        let _ = service
            .dispatch_message(&message_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let current = service
            .message_events
            .get(&message_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing message"));
        assert_eq!(current.value.state, super::MessageState::DeadLettered);
        assert!(
            current
                .value
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("abuse quarantine")
        );

        let stored_quarantine = service
            .abuse_quarantines
            .get("abq_demo")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing quarantine"));
        let mut quarantine = stored_quarantine.value;
        quarantine.state = String::from("released");
        quarantine.released_reason = Some(String::from("manual release"));
        quarantine.released_at = Some(time::OffsetDateTime::now_utc());
        service
            .abuse_quarantines
            .upsert("abq_demo", quarantine, Some(stored_quarantine.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let dead_letters = service
            .dead_letters
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let dead_letter_id = dead_letters[0].1.value.id.to_string();
        let _ = service
            .replay_dead_letter(
                &dead_letter_id,
                ReplayDeadLetterRequest {
                    reason: Some(String::from("quarantine released")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .dispatch_message(&message_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let recovered = service
            .message_events
            .get(&message_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing message after replay"));
        assert_eq!(recovered.value.state, super::MessageState::Delivered);
    }

    #[tokio::test]
    async fn mail_summary_reflects_persisted_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = MailService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_domain(
                CreateDomainRequest {
                    domain: String::from("summary.example"),
                    zone_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let domain_id = service
            .domains
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value.id)
            .unwrap_or_else(|| panic!("missing domain"));
        let stored_domain = service
            .domains
            .get(domain_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("domain missing"));
        let mut domain = stored_domain.value;
        domain.verified = true;
        domain.metadata.touch(sha256_hex(
            format!("{}:verified", domain.id.as_str()).as_bytes(),
        ));
        service
            .domains
            .upsert(
                domain_id.as_str(),
                domain.clone(),
                Some(stored_domain.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_relay_route(
                CreateRelayRouteRequest {
                    domain_id: domain_id.to_string(),
                    destination: String::from("smtp.forwarder.local:2525"),
                    auth_mode: String::from("mtls"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_inbound_route(
                CreateInboundRouteRequest {
                    domain_id: domain_id.to_string(),
                    recipient_pattern: String::from("*"),
                    target: String::from("hook://inbound"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let message_id = AuditId::generate().unwrap_or_else(|error| panic!("{error}"));
        let message = MessageEventRecord {
            id: message_id.clone(),
            domain_id: domain_id.clone(),
            direction: String::from("outbound"),
            from: String::from("alerts@summary.example"),
            to: String::from("ops@example.org"),
            subject_hash: sha256_hex(b"summary"),
            state: MessageState::DeadLettered,
            attempts: 2,
            max_attempts: 5,
            next_attempt_at: None,
            last_error: Some(String::from("timeout")),
            updated_at: OffsetDateTime::now_utc(),
        };
        service
            .message_events
            .create(message_id.as_str(), message.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let dead_letter_id = DeadLetterId::generate().unwrap_or_else(|error| panic!("{error}"));
        let dead_letter = MailDeadLetterRecord {
            id: dead_letter_id.clone(),
            message_id: message_id.clone(),
            domain_id: domain_id.clone(),
            direction: message.direction.clone(),
            from: message.from.clone(),
            to: message.to.clone(),
            attempts: message.attempts,
            last_error: message.last_error.clone().unwrap_or_default(),
            captured_at: OffsetDateTime::now_utc(),
            replay_count: 1,
            last_replayed_at: None,
            last_replay_reason: None,
            metadata: new_metadata(dead_letter_id.as_str()).await,
        };
        service
            .dead_letters
            .create(dead_letter_id.as_str(), dead_letter)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        seed_dns_zone(&service, "zone-summary", "example.com", true).await;
        service
            .dns_records
            .create(
                "record-summary",
                DnsRecordHook {
                    id: String::from("record-summary"),
                    zone_id: String::from("zone-summary"),
                    name: String::from("_spf"),
                    record_type: String::from("TXT"),
                    value: String::from("v=spf1 include:_spf.example -all"),
                    ttl: 60,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .dns_provider_tasks
            .create(
                "task-summary",
                DnsProviderTaskHook {
                    id: String::from("task-summary"),
                    provider: String::from("cloudflare"),
                    action: String::from("sync"),
                    resource_id: String::from("record-summary"),
                    payload: serde_json::json!({"note": "summary"}),
                    status: String::from("pending"),
                    attempt_count: 0,
                    last_attempt_at: None,
                    next_attempt_at: None,
                    last_error: None,
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .abuse_quarantines
            .create(
                "abuse-summary",
                AbuseQuarantineHookRecord {
                    subject_kind: String::from("mail_domain"),
                    subject: domain.domain.clone(),
                    state: String::from("active"),
                    deny_mail_relay: true,
                    expires_at: None,
                    released_at: None,
                    released_reason: None,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .mail_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.domain_count, 1);
        assert_eq!(summary.verified_domain_count, 1);
        assert_eq!(summary.relay_route_count, 1);
        assert_eq!(summary.inbound_route_count, 1);
        assert_eq!(summary.message_event_count, 1);
        assert_eq!(summary.message_state_counts.get("dead_lettered"), Some(&1));
        assert_eq!(summary.dead_letter_count, 1);
        assert_eq!(summary.dead_letter_total_replays, 1);
        assert_eq!(summary.reputation_record_count, 1);
        assert_eq!(summary.reputation_suspended_count, 0);
        assert_eq!(summary.dns_zone_count, 1);
        assert_eq!(summary.dns_zone_verified_count, 1);
        assert_eq!(summary.dns_record_count, 1);
        assert_eq!(summary.dns_provider_task_count, 1);
        assert_eq!(summary.abuse_quarantine_count, 1);
        assert_eq!(summary.abuse_quarantine_denies, 1);
    }
}
