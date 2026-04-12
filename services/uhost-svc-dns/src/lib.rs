//! DNS and domain management service.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use http::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{
    PlatformError, RequestContext, Result, canonicalize_hostname, sha256_hex, validate_domain_name,
    validate_label_value,
};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{AuditLog, DocumentStore, DurableOutbox};
use uhost_types::id::DnsPublicationIntentId;
use uhost_types::{
    AuditActor, AuditId, ChangeRequestId, EventHeader, EventPayload, GovernanceChangeAuthorization,
    GovernanceRequestProvenance, OwnershipScope, PlatformEvent, ResourceMetadata, ServiceEvent,
    ZoneId,
};

const GOVERNANCE_CHANGE_REQUEST_HEADER: &str = "x-uhost-change-request-id";

/// Managed DNS zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneRecord {
    pub id: ZoneId,
    pub domain: String,
    pub verified: bool,
    pub metadata: ResourceMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// DNS record entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: String,
    pub zone_id: ZoneId,
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
    pub metadata: ResourceMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// Durable provider synchronization task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSyncTask {
    pub id: AuditId,
    pub provider: String,
    pub action: String,
    pub resource_id: String,
    pub payload: serde_json::Value,
    pub status: String,
    #[serde(default)]
    pub attempt_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Steering mode for DNS publication intents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsSteeringMode {
    Weighted,
    Priority,
    Geo,
    Latency,
}

impl DnsSteeringMode {
    /// Return the stable string form used in summaries and provider payloads.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Weighted => "weighted",
            Self::Priority => "priority",
            Self::Geo => "geo",
            Self::Latency => "latency",
        }
    }
}

/// Optional health-check hint for one alias answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsAliasHealthCheck {
    pub protocol: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
}

/// One steerable alias answer for a DNS publication intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsPublicationAnswer {
    pub alias: String,
    #[serde(default)]
    pub weight: Option<u16>,
    #[serde(default)]
    pub priority: Option<u16>,
    #[serde(default)]
    pub geo_scope: Option<String>,
    #[serde(default)]
    pub latency_region: Option<String>,
    #[serde(default)]
    pub health_check: Option<DnsAliasHealthCheck>,
}

/// Durable DNS publication intent independent from raw record rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsPublicationIntent {
    pub id: DnsPublicationIntentId,
    pub zone_id: ZoneId,
    pub hostname: String,
    pub steering: DnsSteeringMode,
    pub answers: Vec<DnsPublicationAnswer>,
    pub metadata: ResourceMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_authorization: Option<GovernanceChangeAuthorization>,
}

/// Read-only provider-delivery state for one publication intent task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsPublicationIntentDeliveryState {
    pub publication_intent_id: DnsPublicationIntentId,
    pub hostname: String,
    pub provider_task_id: AuditId,
    pub provider: String,
    pub status: String,
    pub attempt_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GovernanceChangeRequestMirror {
    id: ChangeRequestId,
    state: String,
    #[serde(default, flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateZoneRequest {
    domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateRecordRequest {
    zone_id: String,
    name: String,
    record_type: String,
    value: String,
    ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateDnsAliasHealthCheckRequest {
    protocol: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateDnsPublicationAnswerRequest {
    alias: String,
    #[serde(default)]
    weight: Option<u16>,
    #[serde(default)]
    priority: Option<u16>,
    #[serde(default)]
    geo_scope: Option<String>,
    #[serde(default)]
    latency_region: Option<String>,
    #[serde(default)]
    health_check: Option<CreateDnsAliasHealthCheckRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateDnsPublicationIntentRequest {
    zone_id: String,
    hostname: String,
    steering: String,
    answers: Vec<CreateDnsPublicationAnswerRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProviderTaskFailureRequest {
    error: String,
    #[serde(default)]
    retry_after_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SummaryCounter {
    key: String,
    count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DnsSummaryResponse {
    zones: ZoneSummary,
    records: RecordSummary,
    publication_intents: PublicationIntentSummary,
    provider_tasks: ProviderTaskSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ZoneSummary {
    total: usize,
    verified: usize,
    unverified: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RecordSummary {
    total: usize,
    by_type: Vec<SummaryCounter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PublicationIntentSummary {
    total: usize,
    by_steering: Vec<SummaryCounter>,
    health_checked_answers: usize,
    delivery_states: Vec<SummaryCounter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProviderTaskSummary {
    total: usize,
    by_status: Vec<SummaryCounter>,
}

/// DNS service.
#[derive(Debug, Clone)]
pub struct DnsService {
    zones: DocumentStore<ZoneRecord>,
    records: DocumentStore<DnsRecord>,
    publication_intents: DocumentStore<DnsPublicationIntent>,
    provider_tasks: DocumentStore<ProviderSyncTask>,
    governance_change_requests: DocumentStore<GovernanceChangeRequestMirror>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    state_root: PathBuf,
}

impl DnsService {
    /// Open dns state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("dns");
        Ok(Self {
            zones: DocumentStore::open(root.join("zones.json")).await?,
            records: DocumentStore::open(root.join("records.json")).await?,
            publication_intents: DocumentStore::open(root.join("publication_intents.json")).await?,
            provider_tasks: DocumentStore::open(root.join("provider_tasks.json")).await?,
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

    #[cfg(test)]
    async fn create_zone(&self, request: CreateZoneRequest) -> Result<http::Response<ApiBody>> {
        let context = RequestContext::new()?;
        self.create_zone_with_context(request, &context).await
    }

    async fn create_zone_with_context(
        &self,
        request: CreateZoneRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        self.create_zone_authorized(request, context, None).await
    }

    async fn create_zone_authorized(
        &self,
        request: CreateZoneRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<http::Response<ApiBody>> {
        let id = ZoneId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate zone id").with_detail(error.to_string())
        })?;
        let mut zone = ZoneRecord {
            id: id.clone(),
            domain: validate_domain_name(&request.domain)?,
            verified: false,
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
                zone_mutation_digest(&zone, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut zone.metadata, "dns.mutation_digest");
            zone.change_authorization = Some(authorization.clone());
        }
        self.zones.create(id.as_str(), zone.clone()).await?;
        let provider_task = self
            .enqueue_cloudflare_task(
                "create_zone",
                id.as_str(),
                serde_json::json!({
                    "zone_name": zone.domain.clone(),
                }),
            )
            .await?;
        let mut details = serde_json::json!({
            "domain": zone.domain.clone(),
            "verified": zone.verified,
            "provider_task_id": provider_task.id,
            "provider": provider_task.provider,
            "provider_action": provider_task.action,
        });
        if let Some(authorization) = zone.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "dns.zone.created.v1",
            "zone",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &zone)
    }

    async fn load_zone(&self, zone_id: &ZoneId) -> Result<ZoneRecord> {
        let stored = self
            .zones
            .get(zone_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("zone does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("zone does not exist"));
        }
        Ok(stored.value)
    }

    #[cfg(test)]
    async fn verify_zone(&self, zone_id: &str) -> Result<http::Response<ApiBody>> {
        let context = RequestContext::new()?;
        self.verify_zone_with_context(zone_id, &context).await
    }

    async fn verify_zone_with_context(
        &self,
        zone_id: &str,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let zone_id = ZoneId::parse(zone_id).map_err(|error| {
            PlatformError::invalid("invalid zone_id in path").with_detail(error.to_string())
        })?;
        let stored = self
            .zones
            .get(zone_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("zone does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("zone does not exist"));
        }

        let mut zone = stored.value;
        if zone.verified {
            return json_response(StatusCode::OK, &zone);
        }

        zone.verified = true;
        let stored_zone = self
            .zones
            .upsert(zone_id.as_str(), zone, Some(stored.version))
            .await?;
        self.append_event(
            "dns.zone.verified.v1",
            "zone",
            zone_id.as_str(),
            "verified",
            serde_json::json!({
                "domain": stored_zone.value.domain.clone(),
                "verified": stored_zone.value.verified,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &stored_zone.value)
    }

    #[cfg(test)]
    async fn create_record(&self, request: CreateRecordRequest) -> Result<http::Response<ApiBody>> {
        let context = RequestContext::new()?;
        self.create_record_with_context(request, &context).await
    }

    async fn create_record_with_context(
        &self,
        request: CreateRecordRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        self.create_record_authorized(request, context, None).await
    }

    async fn create_record_authorized(
        &self,
        request: CreateRecordRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<http::Response<ApiBody>> {
        let zone_id = ZoneId::parse(request.zone_id).map_err(|error| {
            PlatformError::invalid("invalid zone_id").with_detail(error.to_string())
        })?;
        let _zone = self.load_zone(&zone_id).await?;
        let canonical_name = if request.name.trim() == "@" {
            String::from("@")
        } else {
            canonicalize_hostname(request.name.trim())?
        };
        let record_type = normalize_record_type(&request.record_type)?;
        let identifier = format!(
            "{}:{}:{}:{}",
            zone_id.as_str(),
            canonical_name,
            record_type,
            sha256_hex(request.value.as_bytes())
        );
        let mut record = DnsRecord {
            id: identifier.clone(),
            zone_id,
            name: canonical_name,
            record_type,
            value: request.value,
            ttl: request.ttl.max(60),
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(identifier.clone()),
                sha256_hex(identifier.as_bytes()),
            ),
            change_authorization: None,
        };
        if let Some(authorization) = self
            .optional_change_authorization(
                context,
                change_request_id,
                record_mutation_digest(&record, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut record.metadata, "dns.mutation_digest");
            record.change_authorization = Some(authorization.clone());
        }
        self.records.create(&identifier, record.clone()).await?;
        let provider_task = self
            .enqueue_cloudflare_task(
                "upsert_record",
                &identifier,
                serde_json::json!({
                    "zone_id": record.zone_id.to_string(),
                    "name": record.name.clone(),
                    "type": record.record_type.clone(),
                    "value": record.value.clone(),
                    "ttl": record.ttl,
                }),
            )
            .await?;
        let mut details = serde_json::json!({
            "zone_id": record.zone_id.to_string(),
            "name": record.name.clone(),
            "record_type": record.record_type.clone(),
            "value": record.value.clone(),
            "ttl": record.ttl,
            "provider_task_id": provider_task.id,
            "provider": provider_task.provider,
            "provider_action": provider_task.action,
        });
        if let Some(authorization) = record.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "dns.record.created.v1",
            "record",
            &identifier,
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    #[cfg(test)]
    async fn create_publication_intent(
        &self,
        request: CreateDnsPublicationIntentRequest,
    ) -> Result<http::Response<ApiBody>> {
        let context = RequestContext::new()?;
        self.create_publication_intent_with_context(request, &context)
            .await
    }

    async fn create_publication_intent_with_context(
        &self,
        request: CreateDnsPublicationIntentRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        self.create_publication_intent_authorized(request, context, None)
            .await
    }

    async fn create_publication_intent_authorized(
        &self,
        request: CreateDnsPublicationIntentRequest,
        context: &RequestContext,
        change_request_id: Option<&str>,
    ) -> Result<http::Response<ApiBody>> {
        let zone_id = ZoneId::parse(request.zone_id).map_err(|error| {
            PlatformError::invalid("invalid zone_id").with_detail(error.to_string())
        })?;
        let zone = self.load_zone(&zone_id).await?;
        let hostname = canonicalize_hostname(&request.hostname)?;
        validate_publication_hostname(&hostname, &zone.domain)?;
        let steering = normalize_steering_mode(&request.steering)?;
        let answers = build_publication_answers(request.answers, steering)?;
        let id = DnsPublicationIntentId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate publication intent id")
                .with_detail(error.to_string())
        })?;
        let mut intent = DnsPublicationIntent {
            id: id.clone(),
            zone_id,
            hostname,
            steering,
            answers,
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
                publication_intent_mutation_digest(&intent, change_request_id)?,
            )
            .await?
        {
            authorization.annotate_metadata(&mut intent.metadata, "dns.mutation_digest");
            intent.change_authorization = Some(authorization.clone());
        }
        self.publication_intents
            .create(id.as_str(), intent.clone())
            .await?;
        let provider_task = self
            .enqueue_cloudflare_task(
                "upsert_publication_intent",
                id.as_str(),
                serde_json::json!({
                    "zone_id": intent.zone_id.to_string(),
                    "hostname": intent.hostname.clone(),
                    "steering": intent.steering.as_str(),
                    "answers": intent.answers.clone(),
                }),
            )
            .await?;
        let mut details = serde_json::json!({
            "zone_id": intent.zone_id.to_string(),
            "hostname": intent.hostname.clone(),
            "steering": intent.steering.as_str(),
            "answer_count": intent.answers.len(),
            "health_checked_answers": intent
                .answers
                .iter()
                .filter(|answer| answer.health_check.is_some())
                .count(),
            "provider_task_id": provider_task.id,
            "provider": provider_task.provider,
            "provider_action": provider_task.action,
        });
        if let Some(authorization) = intent.change_authorization.as_ref() {
            append_change_authorization_details(&mut details, authorization);
        }
        self.append_event(
            "dns.publication_intent.created.v1",
            "publication_intent",
            id.as_str(),
            "created",
            details,
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &intent)
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

    async fn enqueue_cloudflare_task(
        &self,
        action: &str,
        resource_id: &str,
        payload: serde_json::Value,
    ) -> Result<ProviderSyncTask> {
        let now = OffsetDateTime::now_utc();
        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate provider sync task id")
                .with_detail(error.to_string())
        })?;
        let task = ProviderSyncTask {
            id: id.clone(),
            provider: String::from("cloudflare"),
            action: String::from(action),
            resource_id: String::from(resource_id),
            payload,
            status: String::from("pending"),
            attempt_count: 0,
            last_attempt_at: None,
            next_attempt_at: None,
            last_error: None,
            created_at: now,
            updated_at: now,
        };
        self.provider_tasks
            .create(id.as_str(), task.clone())
            .await?;
        Ok(task)
    }

    #[cfg(test)]
    async fn mark_provider_task_delivered(&self, task_id: &str) -> Result<http::Response<ApiBody>> {
        let context = RequestContext::new()?;
        self.mark_provider_task_delivered_with_context(task_id, &context)
            .await
    }

    #[cfg(test)]
    async fn mark_provider_task_failed(
        &self,
        task_id: &str,
        request: ProviderTaskFailureRequest,
    ) -> Result<http::Response<ApiBody>> {
        let context = RequestContext::new()?;
        self.mark_provider_task_failed_with_context(task_id, request, &context)
            .await
    }

    async fn mark_provider_task_delivered_with_context(
        &self,
        task_id: &str,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let stored = self
            .provider_tasks
            .get(task_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("provider task does not exist"))?;
        let mut task = stored.value;
        let now = OffsetDateTime::now_utc();
        task.status = String::from("delivered");
        task.attempt_count = task.attempt_count.saturating_add(1);
        task.last_attempt_at = Some(now);
        task.next_attempt_at = None;
        task.updated_at = now;
        task.last_error = None;
        self.provider_tasks
            .upsert(task_id, task.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "dns.provider_task.delivered.v1",
            "provider_task",
            task_id,
            "delivered",
            serde_json::json!({
                "provider": task.provider,
                "action": task.action,
                "resource_id": task.resource_id,
                "status": task.status,
                "attempt_count": task.attempt_count,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &task)
    }

    async fn mark_provider_task_failed_with_context(
        &self,
        task_id: &str,
        request: ProviderTaskFailureRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let stored = self
            .provider_tasks
            .get(task_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("provider task does not exist"))?;
        let mut task = stored.value;
        let error = normalize_provider_task_error(&request.error)?;
        let now = OffsetDateTime::now_utc();
        task.attempt_count = task.attempt_count.saturating_add(1);
        task.last_attempt_at = Some(now);
        task.last_error = Some(error.clone());
        task.next_attempt_at = request
            .retry_after_seconds
            .map(|seconds| now + Duration::seconds(i64::from(seconds)));
        task.status = if task.next_attempt_at.is_some() {
            String::from("retry_pending")
        } else {
            String::from("failed")
        };
        task.updated_at = now;
        self.provider_tasks
            .upsert(task_id, task.clone(), Some(stored.version))
            .await?;
        let (event_type, action) = if task.next_attempt_at.is_some() {
            ("dns.provider_task.retry_scheduled.v1", "retry_scheduled")
        } else {
            ("dns.provider_task.failed.v1", "failed")
        };
        self.append_event(
            event_type,
            "provider_task",
            task_id,
            action,
            serde_json::json!({
                "provider": task.provider,
                "action": task.action,
                "resource_id": task.resource_id,
                "status": task.status,
                "attempt_count": task.attempt_count,
                "last_error": task.last_error,
                "next_attempt_at": task.next_attempt_at,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &task)
    }

    async fn list_zones(&self) -> Result<Vec<ZoneRecord>> {
        Ok(collect_active_values(self.zones.list().await?))
    }

    async fn list_records(&self) -> Result<Vec<DnsRecord>> {
        Ok(collect_active_values(self.records.list().await?))
    }

    async fn list_publication_intents(&self) -> Result<Vec<DnsPublicationIntent>> {
        Ok(collect_active_values(
            self.publication_intents.list().await?,
        ))
    }

    async fn list_provider_tasks(&self) -> Result<Vec<ProviderSyncTask>> {
        Ok(collect_active_values(self.provider_tasks.list().await?))
    }

    async fn list_publication_intent_delivery_states(
        &self,
    ) -> Result<Vec<DnsPublicationIntentDeliveryState>> {
        let intents = self
            .list_publication_intents()
            .await?
            .into_iter()
            .map(|intent| (intent.id.to_string(), intent))
            .collect::<BTreeMap<_, _>>();
        let mut states = Vec::new();
        for task in self.list_provider_tasks().await? {
            if task.action != "upsert_publication_intent" {
                continue;
            }
            let Some(intent) = intents.get(&task.resource_id) else {
                continue;
            };
            states.push(DnsPublicationIntentDeliveryState {
                publication_intent_id: intent.id.clone(),
                hostname: intent.hostname.clone(),
                provider_task_id: task.id,
                provider: task.provider,
                status: task.status,
                attempt_count: task.attempt_count,
                last_attempt_at: task.last_attempt_at,
                next_attempt_at: task.next_attempt_at,
                last_error: task.last_error,
                updated_at: task.updated_at,
            });
        }
        states.sort_by(|left, right| {
            left.hostname
                .cmp(&right.hostname)
                .then_with(|| left.provider_task_id.cmp(&right.provider_task_id))
        });
        Ok(states)
    }

    async fn summary_report(&self) -> Result<http::Response<ApiBody>> {
        let zones = self.list_zones().await?;
        let verified_zones = zones.iter().filter(|zone| zone.verified).count();

        let records = self.list_records().await?;
        let mut records_by_type = BTreeMap::<String, usize>::new();
        for record in &records {
            let entry = records_by_type
                .entry(record.record_type.clone())
                .or_insert(0);
            *entry += 1;
        }

        let publication_intents = self.list_publication_intents().await?;
        let mut publication_intents_by_steering = BTreeMap::<String, usize>::new();
        let mut health_checked_answers = 0_usize;
        for intent in &publication_intents {
            let entry = publication_intents_by_steering
                .entry(String::from(intent.steering.as_str()))
                .or_insert(0);
            *entry += 1;
            health_checked_answers += intent
                .answers
                .iter()
                .filter(|answer| answer.health_check.is_some())
                .count();
        }
        let publication_intent_delivery_states =
            self.list_publication_intent_delivery_states().await?;
        let mut publication_intent_delivery_by_status = BTreeMap::<String, usize>::new();
        for delivery_state in &publication_intent_delivery_states {
            let entry = publication_intent_delivery_by_status
                .entry(delivery_state.status.clone())
                .or_insert(0);
            *entry += 1;
        }

        let provider_tasks = self.list_provider_tasks().await?;
        let mut provider_tasks_by_status = BTreeMap::<String, usize>::new();
        for task in &provider_tasks {
            let entry = provider_tasks_by_status
                .entry(task.status.trim().to_ascii_lowercase())
                .or_insert(0);
            *entry += 1;
        }

        let summary = DnsSummaryResponse {
            zones: ZoneSummary {
                total: zones.len(),
                verified: verified_zones,
                unverified: zones.len().saturating_sub(verified_zones),
            },
            records: RecordSummary {
                total: records.len(),
                by_type: map_summary_counters(records_by_type),
            },
            publication_intents: PublicationIntentSummary {
                total: publication_intents.len(),
                by_steering: map_summary_counters(publication_intents_by_steering),
                health_checked_answers,
                delivery_states: map_summary_counters(publication_intent_delivery_by_status),
            },
            provider_tasks: ProviderTaskSummary {
                total: provider_tasks.len(),
                by_status: map_summary_counters(provider_tasks_by_status),
            },
        };
        json_response(StatusCode::OK, &summary)
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
        let event = PlatformEvent {
            header: EventHeader {
                event_id: AuditId::generate().map_err(|error| {
                    PlatformError::unavailable("failed to allocate audit id")
                        .with_detail(error.to_string())
                })?,
                event_type: event_type.to_owned(),
                schema_version: 1,
                source_service: String::from("dns"),
                emitted_at: OffsetDateTime::now_utc(),
                actor: AuditActor {
                    subject: actor_subject,
                    actor_type,
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
            .enqueue("dns.events.v1", event, Some(&idempotency))
            .await?;
        Ok(())
    }
}

impl HttpService for DnsService {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/dns")];
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
                (Method::GET, ["dns"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                    }),
                )
                .map(Some),
                (Method::GET, ["dns", "zones"]) => {
                    json_response(StatusCode::OK, &self.list_zones().await?).map(Some)
                }
                (Method::GET, ["dns", "summary"]) => self.summary_report().await.map(Some),
                (Method::POST, ["dns", "zones"]) => {
                    let body: CreateZoneRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_zone_authorized(body, &context, Some(change_request_id))
                            .await
                            .map(Some),
                        None => self
                            .create_zone_with_context(body, &context)
                            .await
                            .map(Some),
                    }
                }
                (Method::POST, ["dns", "zones", zone_id, "verify"]) => self
                    .verify_zone_with_context(zone_id, &context)
                    .await
                    .map(Some),
                (Method::GET, ["dns", "records"]) => {
                    json_response(StatusCode::OK, &self.list_records().await?).map(Some)
                }
                (Method::POST, ["dns", "records"]) => {
                    let body: CreateRecordRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_record_authorized(body, &context, Some(change_request_id))
                            .await
                            .map(Some),
                        None => self
                            .create_record_with_context(body, &context)
                            .await
                            .map(Some),
                    }
                }
                (Method::GET, ["dns", "publication-intents"]) => {
                    json_response(StatusCode::OK, &self.list_publication_intents().await?).map(Some)
                }
                (Method::GET, ["dns", "publication-intents", "delivery"]) => json_response(
                    StatusCode::OK,
                    &self.list_publication_intent_delivery_states().await?,
                )
                .map(Some),
                (Method::POST, ["dns", "publication-intents"]) => {
                    let body: CreateDnsPublicationIntentRequest = parse_json(request).await?;
                    match governance_change_request_id.as_deref() {
                        Some(change_request_id) => self
                            .create_publication_intent_authorized(
                                body,
                                &context,
                                Some(change_request_id),
                            )
                            .await
                            .map(Some),
                        None => self
                            .create_publication_intent_with_context(body, &context)
                            .await
                            .map(Some),
                    }
                }
                (Method::GET, ["dns", "provider-tasks"]) => {
                    json_response(StatusCode::OK, &self.list_provider_tasks().await?).map(Some)
                }
                (Method::GET, ["dns", "outbox"]) => {
                    let messages = self.outbox.list_all().await?;
                    json_response(StatusCode::OK, &messages).map(Some)
                }
                (Method::POST, ["dns", "provider-tasks", task_id, "deliver"]) => self
                    .mark_provider_task_delivered_with_context(task_id, &context)
                    .await
                    .map(Some),
                (Method::POST, ["dns", "provider-tasks", task_id, "fail"]) => {
                    let body: ProviderTaskFailureRequest = parse_json(request).await?;
                    self.mark_provider_task_failed_with_context(task_id, body, &context)
                        .await
                        .map(Some)
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

fn zone_mutation_digest(
    zone: &ZoneRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "domain": zone.domain,
        "verified": zone.verified,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode dns zone mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn record_mutation_digest(
    record: &DnsRecord,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "zone_id": record.zone_id,
        "name": record.name,
        "record_type": record.record_type,
        "value": record.value,
        "ttl": record.ttl,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode dns record mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn publication_intent_mutation_digest(
    intent: &DnsPublicationIntent,
    change_request_id: Option<&str>,
) -> Result<Option<String>> {
    let Some(change_request_id) = change_request_id else {
        return Ok(None);
    };
    let encoded = serde_json::to_vec(&serde_json::json!({
        "change_request_id": change_request_id,
        "zone_id": intent.zone_id,
        "hostname": intent.hostname,
        "steering": intent.steering,
        "answers": intent.answers,
    }))
    .map_err(|error| {
        PlatformError::unavailable("failed to encode dns publication intent mutation digest")
            .with_detail(error.to_string())
    })?;
    Ok(Some(sha256_hex(&encoded)))
}

fn normalize_record_type(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_uppercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("record type may not be empty"));
    }
    if !normalized
        .chars()
        .all(|character| character.is_ascii_alphanumeric())
    {
        return Err(PlatformError::invalid(
            "record type must contain only ASCII letters and digits",
        ));
    }
    Ok(normalized)
}

fn normalize_provider_task_error(value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(
            "provider task failure error may not be empty",
        ));
    }
    if normalized.len() > 512 {
        return Err(PlatformError::invalid(
            "provider task failure error is too long",
        ));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "provider task failure error may not contain control characters",
        ));
    }
    Ok(normalized.to_owned())
}

fn validate_publication_hostname(hostname: &str, zone_domain: &str) -> Result<()> {
    let allowed_suffix = format!(".{zone_domain}");
    if hostname == zone_domain || hostname.ends_with(&allowed_suffix) {
        return Ok(());
    }
    Err(PlatformError::forbidden(
        "zone_id is not authorized for this publication hostname",
    ))
}

fn normalize_steering_mode(value: &str) -> Result<DnsSteeringMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "weighted" => Ok(DnsSteeringMode::Weighted),
        "priority" => Ok(DnsSteeringMode::Priority),
        "geo" => Ok(DnsSteeringMode::Geo),
        "latency" => Ok(DnsSteeringMode::Latency),
        _ => Err(PlatformError::invalid(
            "steering must be one of weighted, priority, geo, latency",
        )),
    }
}

fn normalize_optional_selector(field: &str, value: Option<String>) -> Result<Option<String>> {
    match value {
        Some(value) => {
            let normalized = validate_label_value(value.trim())?.to_ascii_lowercase();
            if normalized.is_empty() {
                return Err(PlatformError::invalid(format!("{field} may not be empty")));
            }
            Ok(Some(normalized))
        }
        None => Ok(None),
    }
}

fn normalize_dns_health_check_path(path: Option<String>, protocol: &str) -> Result<Option<String>> {
    match protocol {
        "http" | "https" => {
            let path = path.unwrap_or_else(|| String::from("/healthz"));
            if path.trim().is_empty() || !path.starts_with('/') {
                return Err(PlatformError::invalid(
                    "health check path must be an absolute path",
                ));
            }
            Ok(Some(path))
        }
        _ => {
            if path
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            {
                return Err(PlatformError::invalid(
                    "tcp health checks may not set a request path",
                ));
            }
            Ok(None)
        }
    }
}

fn build_health_check(request: CreateDnsAliasHealthCheckRequest) -> Result<DnsAliasHealthCheck> {
    let protocol = request.protocol.trim().to_ascii_lowercase();
    if !matches!(protocol.as_str(), "http" | "https" | "tcp") {
        return Err(PlatformError::invalid(
            "health check protocol must be one of http, https, tcp",
        ));
    }
    if matches!(request.port, Some(0)) {
        return Err(PlatformError::invalid(
            "health check port must be greater than zero",
        ));
    }
    Ok(DnsAliasHealthCheck {
        path: normalize_dns_health_check_path(request.path, protocol.as_str())?,
        protocol,
        port: request.port,
    })
}

fn build_publication_answers(
    requests: Vec<CreateDnsPublicationAnswerRequest>,
    steering: DnsSteeringMode,
) -> Result<Vec<DnsPublicationAnswer>> {
    if requests.is_empty() {
        return Err(PlatformError::invalid(
            "publication intent requires at least one alias answer",
        ));
    }

    let mut aliases = BTreeSet::new();
    let mut selector_values = BTreeSet::new();
    let mut answers = Vec::with_capacity(requests.len());
    for request in requests {
        let alias = canonicalize_hostname(&request.alias)?;
        if !aliases.insert(alias.clone()) {
            return Err(PlatformError::conflict(
                "publication intent alias answers must be unique",
            ));
        }
        let health_check = request.health_check.map(build_health_check).transpose()?;
        match steering {
            DnsSteeringMode::Weighted => {
                if request.priority.is_some()
                    || request.geo_scope.is_some()
                    || request.latency_region.is_some()
                {
                    return Err(PlatformError::invalid(
                        "weighted answers may only set weight and health_check",
                    ));
                }
                let weight = request
                    .weight
                    .ok_or_else(|| PlatformError::invalid("weighted answers require weight"))?;
                if weight == 0 {
                    return Err(PlatformError::invalid(
                        "weighted answer weight must be greater than zero",
                    ));
                }
                answers.push(DnsPublicationAnswer {
                    alias,
                    weight: Some(weight),
                    priority: None,
                    geo_scope: None,
                    latency_region: None,
                    health_check,
                });
            }
            DnsSteeringMode::Priority => {
                if request.weight.is_some()
                    || request.geo_scope.is_some()
                    || request.latency_region.is_some()
                {
                    return Err(PlatformError::invalid(
                        "priority answers may only set priority and health_check",
                    ));
                }
                let priority = request
                    .priority
                    .ok_or_else(|| PlatformError::invalid("priority answers require priority"))?;
                answers.push(DnsPublicationAnswer {
                    alias,
                    weight: None,
                    priority: Some(priority),
                    geo_scope: None,
                    latency_region: None,
                    health_check,
                });
            }
            DnsSteeringMode::Geo => {
                if request.weight.is_some()
                    || request.priority.is_some()
                    || request.latency_region.is_some()
                {
                    return Err(PlatformError::invalid(
                        "geo answers may only set geo_scope and health_check",
                    ));
                }
                let geo_scope = normalize_optional_selector("geo_scope", request.geo_scope)?
                    .ok_or_else(|| PlatformError::invalid("geo answers require geo_scope"))?;
                if !selector_values.insert(format!("geo:{geo_scope}")) {
                    return Err(PlatformError::conflict(
                        "geo answers must use unique geo_scope values",
                    ));
                }
                answers.push(DnsPublicationAnswer {
                    alias,
                    weight: None,
                    priority: None,
                    geo_scope: Some(geo_scope),
                    latency_region: None,
                    health_check,
                });
            }
            DnsSteeringMode::Latency => {
                if request.weight.is_some()
                    || request.priority.is_some()
                    || request.geo_scope.is_some()
                {
                    return Err(PlatformError::invalid(
                        "latency answers may only set latency_region and health_check",
                    ));
                }
                let latency_region =
                    normalize_optional_selector("latency_region", request.latency_region)?
                        .ok_or_else(|| {
                            PlatformError::invalid("latency answers require latency_region")
                        })?;
                if !selector_values.insert(format!("latency:{latency_region}")) {
                    return Err(PlatformError::conflict(
                        "latency answers must use unique latency_region values",
                    ));
                }
                answers.push(DnsPublicationAnswer {
                    alias,
                    weight: None,
                    priority: None,
                    geo_scope: None,
                    latency_region: Some(latency_region),
                    health_check,
                });
            }
        }
    }
    Ok(answers)
}

fn collect_active_values<T>(records: Vec<(String, uhost_store::StoredDocument<T>)>) -> Vec<T> {
    let mut active = BTreeMap::new();
    for (key, record) in records {
        if !record.deleted {
            active.insert(key, record.value);
        }
    }
    active.into_values().collect()
}

fn map_summary_counters(counters: BTreeMap<String, usize>) -> Vec<SummaryCounter> {
    counters
        .into_iter()
        .map(|(key, count)| SummaryCounter { key, count })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use bytes::Bytes;
    use http_body_util::{BodyExt as _, Full};
    use serde::de::DeserializeOwned;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_state_root() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "uhost-svc-dns-tests-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp dir");
        path
    }

    async fn response_json<T: DeserializeOwned>(response: http::Response<ApiBody>) -> T {
        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect response body")
            .to_bytes();
        serde_json::from_slice(&body).expect("json body")
    }

    fn request_context() -> RequestContext {
        RequestContext::new().unwrap_or_else(|error| panic!("{error}"))
    }

    fn service_request(
        method: &str,
        uri: &str,
        body: Option<&str>,
    ) -> Request<uhost_runtime::RequestBody> {
        let mut builder = Request::builder().method(method).uri(uri);
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        builder
            .body(uhost_runtime::RequestBody::Right(Full::new(Bytes::from(
                body.unwrap_or_default().to_owned(),
            ))))
            .unwrap_or_else(|error| panic!("{error}"))
    }

    async fn dispatch_request(
        service: &DnsService,
        method: &str,
        uri: &str,
        body: Option<&str>,
    ) -> http::Response<ApiBody> {
        match service
            .handle(service_request(method, uri, body), request_context())
            .await
        {
            Ok(Some(response)) => response,
            Ok(None) => panic!("route {method} {uri} was not handled"),
            Err(error) => panic!("{error}"),
        }
    }

    async fn seed_governance_change_request(service: &DnsService, state: &str) -> String {
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

    #[tokio::test]
    async fn create_zone_starts_unverified_and_verify_zone_marks_it_verified() {
        let service = DnsService::open(temp_state_root())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_zone: ZoneRecord = response_json(
            service
                .create_zone(CreateZoneRequest {
                    domain: String::from("example.com"),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert!(!created_zone.verified);

        let verified_zone: ZoneRecord = response_json(
            service
                .verify_zone(created_zone.id.as_str())
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert!(verified_zone.verified);

        let stored_zone = service
            .zones
            .get(created_zone.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing verified zone"));
        assert!(stored_zone.value.verified);
    }

    #[tokio::test]
    async fn create_zone_persists_change_authorization_when_governed() {
        let service = DnsService::open(temp_state_root())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("dns.operator");
        let change_request_id = seed_governance_change_request(&service, "approved").await;

        let zone: ZoneRecord = response_json(
            service
                .create_zone_authorized(
                    CreateZoneRequest {
                        domain: String::from("governed.example.com"),
                    },
                    &context,
                    Some(change_request_id.as_str()),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let authorization = zone
            .change_authorization
            .as_ref()
            .unwrap_or_else(|| panic!("missing zone change authorization"));
        assert_eq!(
            authorization.change_request_id.as_str(),
            change_request_id.as_str()
        );
        assert_eq!(authorization.mutation_digest.len(), 64);
        assert_eq!(
            zone.metadata
                .annotations
                .get("governance.change_request_id")
                .map(String::as_str),
            Some(change_request_id.as_str())
        );
        assert_eq!(
            zone.metadata
                .annotations
                .get("dns.mutation_digest")
                .map(String::len),
            Some(64)
        );
    }

    #[tokio::test]
    async fn create_record_normalizes_root_name_record_type_and_ttl() {
        let service = DnsService::open(temp_state_root()).await.unwrap();
        let zone: ZoneRecord = response_json(
            service
                .create_zone(CreateZoneRequest {
                    domain: String::from("Example.COM."),
                })
                .await
                .unwrap(),
        )
        .await;

        let record: DnsRecord = response_json(
            service
                .create_record(CreateRecordRequest {
                    zone_id: zone.id.to_string(),
                    name: String::from(" @ "),
                    record_type: String::from("txt"),
                    value: String::from("v=spf1 -all"),
                    ttl: 1,
                })
                .await
                .unwrap(),
        )
        .await;

        assert_eq!(record.name, "@");
        assert_eq!(record.record_type, "TXT");
        assert_eq!(record.ttl, 60);
    }

    #[tokio::test]
    async fn create_record_rejects_deleted_zones_and_lists_skip_deleted_entries() {
        let service = DnsService::open(temp_state_root()).await.unwrap();
        let zone: ZoneRecord = response_json(
            service
                .create_zone(CreateZoneRequest {
                    domain: String::from("example.com"),
                })
                .await
                .unwrap(),
        )
        .await;
        let record: DnsRecord = response_json(
            service
                .create_record(CreateRecordRequest {
                    zone_id: zone.id.to_string(),
                    name: String::from("www"),
                    record_type: String::from("A"),
                    value: String::from("192.0.2.10"),
                    ttl: 300,
                })
                .await
                .unwrap(),
        )
        .await;

        service
            .zones
            .soft_delete(zone.id.as_str(), Some(1))
            .await
            .unwrap();
        service
            .records
            .soft_delete(record.id.as_str(), Some(1))
            .await
            .unwrap();

        let zone_error = service
            .create_record(CreateRecordRequest {
                zone_id: zone.id.to_string(),
                name: String::from("api"),
                record_type: String::from("A"),
                value: String::from("192.0.2.11"),
                ttl: 300,
            })
            .await
            .expect_err("deleted zone should be rejected");
        assert!(zone_error.to_string().contains("zone does not exist"));

        let zones: Vec<ZoneRecord> = service.list_zones().await.unwrap();
        assert!(zones.is_empty());

        let records: Vec<DnsRecord> = service.list_records().await.unwrap();
        assert!(records.is_empty());

        let tasks: Vec<ProviderSyncTask> = service.list_provider_tasks().await.unwrap();
        assert!(!tasks.is_empty());
        assert_eq!(tasks.len(), 2);
    }

    #[tokio::test]
    async fn create_publication_intent_supports_all_steering_modes() {
        let service = DnsService::open(temp_state_root()).await.unwrap();
        let zone: ZoneRecord = response_json(
            service
                .create_zone(CreateZoneRequest {
                    domain: String::from("example.com"),
                })
                .await
                .unwrap(),
        )
        .await;

        let weighted: DnsPublicationIntent = response_json(
            service
                .create_publication_intent(CreateDnsPublicationIntentRequest {
                    zone_id: zone.id.to_string(),
                    hostname: String::from("api.example.com"),
                    steering: String::from("weighted"),
                    answers: vec![
                        CreateDnsPublicationAnswerRequest {
                            alias: String::from("use1.edge.example.net"),
                            weight: Some(90),
                            priority: None,
                            geo_scope: None,
                            latency_region: None,
                            health_check: Some(CreateDnsAliasHealthCheckRequest {
                                protocol: String::from("https"),
                                path: None,
                                port: Some(443),
                            }),
                        },
                        CreateDnsPublicationAnswerRequest {
                            alias: String::from("usw2.edge.example.net"),
                            weight: Some(10),
                            priority: None,
                            geo_scope: None,
                            latency_region: None,
                            health_check: None,
                        },
                    ],
                })
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(weighted.steering, DnsSteeringMode::Weighted);
        assert_eq!(weighted.answers[0].weight, Some(90));
        assert_eq!(
            weighted.answers[0]
                .health_check
                .as_ref()
                .and_then(|check| check.path.as_deref()),
            Some("/healthz")
        );

        let priority: DnsPublicationIntent = response_json(
            service
                .create_publication_intent(CreateDnsPublicationIntentRequest {
                    zone_id: zone.id.to_string(),
                    hostname: String::from("failover.example.com"),
                    steering: String::from("priority"),
                    answers: vec![
                        CreateDnsPublicationAnswerRequest {
                            alias: String::from("primary.edge.example.net"),
                            weight: None,
                            priority: Some(10),
                            geo_scope: None,
                            latency_region: None,
                            health_check: None,
                        },
                        CreateDnsPublicationAnswerRequest {
                            alias: String::from("secondary.edge.example.net"),
                            weight: None,
                            priority: Some(20),
                            geo_scope: None,
                            latency_region: None,
                            health_check: None,
                        },
                    ],
                })
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(priority.steering, DnsSteeringMode::Priority);
        assert_eq!(priority.answers[0].priority, Some(10));

        let geo: DnsPublicationIntent = response_json(
            service
                .create_publication_intent(CreateDnsPublicationIntentRequest {
                    zone_id: zone.id.to_string(),
                    hostname: String::from("geo.example.com"),
                    steering: String::from("geo"),
                    answers: vec![
                        CreateDnsPublicationAnswerRequest {
                            alias: String::from("eu.edge.example.net"),
                            weight: None,
                            priority: None,
                            geo_scope: Some(String::from("region/eu")),
                            latency_region: None,
                            health_check: None,
                        },
                        CreateDnsPublicationAnswerRequest {
                            alias: String::from("na.edge.example.net"),
                            weight: None,
                            priority: None,
                            geo_scope: Some(String::from("region/na")),
                            latency_region: None,
                            health_check: None,
                        },
                    ],
                })
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(geo.steering, DnsSteeringMode::Geo);
        assert_eq!(geo.answers[0].geo_scope.as_deref(), Some("region/eu"));

        let latency: DnsPublicationIntent = response_json(
            service
                .create_publication_intent(CreateDnsPublicationIntentRequest {
                    zone_id: zone.id.to_string(),
                    hostname: String::from("latency.example.com"),
                    steering: String::from("latency"),
                    answers: vec![
                        CreateDnsPublicationAnswerRequest {
                            alias: String::from("use1.edge.example.net"),
                            weight: None,
                            priority: None,
                            geo_scope: None,
                            latency_region: Some(String::from("us-east-1")),
                            health_check: None,
                        },
                        CreateDnsPublicationAnswerRequest {
                            alias: String::from("euw1.edge.example.net"),
                            weight: None,
                            priority: None,
                            geo_scope: None,
                            latency_region: Some(String::from("eu-west-1")),
                            health_check: Some(CreateDnsAliasHealthCheckRequest {
                                protocol: String::from("tcp"),
                                path: None,
                                port: Some(443),
                            }),
                        },
                    ],
                })
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(latency.steering, DnsSteeringMode::Latency);
        assert_eq!(
            latency.answers[1].latency_region.as_deref(),
            Some("eu-west-1")
        );

        let intents = service.list_publication_intents().await.unwrap();
        assert_eq!(intents.len(), 4);

        let tasks = service.list_provider_tasks().await.unwrap();
        assert_eq!(tasks.len(), 5);
        assert!(
            tasks
                .iter()
                .any(|task| task.action == "upsert_publication_intent"
                    && task.resource_id == weighted.id.to_string())
        );
    }

    #[tokio::test]
    async fn create_publication_intent_rejects_invalid_weighted_shape() {
        let service = DnsService::open(temp_state_root()).await.unwrap();
        let zone: ZoneRecord = response_json(
            service
                .create_zone(CreateZoneRequest {
                    domain: String::from("example.com"),
                })
                .await
                .unwrap(),
        )
        .await;

        let error = service
            .create_publication_intent(CreateDnsPublicationIntentRequest {
                zone_id: zone.id.to_string(),
                hostname: String::from("api.example.com"),
                steering: String::from("weighted"),
                answers: vec![CreateDnsPublicationAnswerRequest {
                    alias: String::from("use1.edge.example.net"),
                    weight: None,
                    priority: Some(10),
                    geo_scope: None,
                    latency_region: None,
                    health_check: None,
                }],
            })
            .await
            .expect_err("invalid weighted answer shape should be rejected");

        assert!(
            error
                .to_string()
                .contains("weighted answers may only set weight and health_check")
        );
    }

    #[tokio::test]
    async fn create_publication_intent_persists_governance_and_provider_payload() {
        let service = DnsService::open(temp_state_root())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("dns.operator");
        let change_request_id = seed_governance_change_request(&service, "approved").await;
        let zone: ZoneRecord = response_json(
            service
                .create_zone(CreateZoneRequest {
                    domain: String::from("example.com"),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let intent: DnsPublicationIntent = response_json(
            service
                .create_publication_intent_authorized(
                    CreateDnsPublicationIntentRequest {
                        zone_id: zone.id.to_string(),
                        hostname: String::from("api.example.com"),
                        steering: String::from("weighted"),
                        answers: vec![CreateDnsPublicationAnswerRequest {
                            alias: String::from("use1.edge.example.net"),
                            weight: Some(100),
                            priority: None,
                            geo_scope: None,
                            latency_region: None,
                            health_check: Some(CreateDnsAliasHealthCheckRequest {
                                protocol: String::from("https"),
                                path: Some(String::from("/readyz")),
                                port: Some(443),
                            }),
                        }],
                    },
                    &context,
                    Some(change_request_id.as_str()),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let authorization = intent
            .change_authorization
            .as_ref()
            .unwrap_or_else(|| panic!("missing publication intent change authorization"));
        assert_eq!(authorization.change_request_id.as_str(), change_request_id);
        assert_eq!(authorization.mutation_digest.len(), 64);
        assert_eq!(
            intent
                .metadata
                .annotations
                .get("governance.change_request_id")
                .map(String::as_str),
            Some(change_request_id.as_str())
        );
        assert_eq!(
            intent
                .metadata
                .annotations
                .get("dns.mutation_digest")
                .map(String::len),
            Some(64)
        );

        let provider_task = service
            .list_provider_tasks()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|task| task.resource_id == intent.id.to_string())
            .unwrap_or_else(|| panic!("missing provider task for publication intent"));
        assert_eq!(provider_task.action, "upsert_publication_intent");
        assert_eq!(
            provider_task.payload["hostname"],
            serde_json::json!("api.example.com")
        );
        assert_eq!(
            provider_task.payload["steering"],
            serde_json::json!("weighted")
        );
        assert_eq!(
            provider_task.payload["answers"][0]["health_check"]["path"],
            serde_json::json!("/readyz")
        );
    }

    #[tokio::test]
    async fn create_publication_intent_rejects_out_of_zone_hostname_and_duplicate_selectors() {
        let service = DnsService::open(temp_state_root()).await.unwrap();
        let zone: ZoneRecord = response_json(
            service
                .create_zone(CreateZoneRequest {
                    domain: String::from("example.com"),
                })
                .await
                .unwrap(),
        )
        .await;

        let hostname_error = service
            .create_publication_intent(CreateDnsPublicationIntentRequest {
                zone_id: zone.id.to_string(),
                hostname: String::from("api.other.example"),
                steering: String::from("weighted"),
                answers: vec![CreateDnsPublicationAnswerRequest {
                    alias: String::from("use1.edge.example.net"),
                    weight: Some(100),
                    priority: None,
                    geo_scope: None,
                    latency_region: None,
                    health_check: None,
                }],
            })
            .await
            .expect_err("hostname outside the zone should be rejected");
        assert!(
            hostname_error
                .to_string()
                .contains("zone_id is not authorized for this publication hostname")
        );

        let geo_error = service
            .create_publication_intent(CreateDnsPublicationIntentRequest {
                zone_id: zone.id.to_string(),
                hostname: String::from("geo.example.com"),
                steering: String::from("geo"),
                answers: vec![
                    CreateDnsPublicationAnswerRequest {
                        alias: String::from("eu-a.edge.example.net"),
                        weight: None,
                        priority: None,
                        geo_scope: Some(String::from("region/eu")),
                        latency_region: None,
                        health_check: None,
                    },
                    CreateDnsPublicationAnswerRequest {
                        alias: String::from("eu-b.edge.example.net"),
                        weight: None,
                        priority: None,
                        geo_scope: Some(String::from("region/eu")),
                        latency_region: None,
                        health_check: None,
                    },
                ],
            })
            .await
            .expect_err("duplicate geo selectors should be rejected");
        assert!(
            geo_error
                .to_string()
                .contains("geo answers must use unique geo_scope values")
        );

        let latency_error = service
            .create_publication_intent(CreateDnsPublicationIntentRequest {
                zone_id: zone.id.to_string(),
                hostname: String::from("latency.example.com"),
                steering: String::from("latency"),
                answers: vec![
                    CreateDnsPublicationAnswerRequest {
                        alias: String::from("use1-a.edge.example.net"),
                        weight: None,
                        priority: None,
                        geo_scope: None,
                        latency_region: Some(String::from("us-east-1")),
                        health_check: None,
                    },
                    CreateDnsPublicationAnswerRequest {
                        alias: String::from("use1-b.edge.example.net"),
                        weight: None,
                        priority: None,
                        geo_scope: None,
                        latency_region: Some(String::from("us-east-1")),
                        health_check: None,
                    },
                ],
            })
            .await
            .expect_err("duplicate latency selectors should be rejected");
        assert!(
            latency_error
                .to_string()
                .contains("latency answers must use unique latency_region values")
        );
    }

    #[tokio::test]
    async fn create_publication_intent_rejects_invalid_health_check_shape() {
        let service = DnsService::open(temp_state_root()).await.unwrap();
        let zone: ZoneRecord = response_json(
            service
                .create_zone(CreateZoneRequest {
                    domain: String::from("example.com"),
                })
                .await
                .unwrap(),
        )
        .await;

        let error = service
            .create_publication_intent(CreateDnsPublicationIntentRequest {
                zone_id: zone.id.to_string(),
                hostname: String::from("api.example.com"),
                steering: String::from("weighted"),
                answers: vec![CreateDnsPublicationAnswerRequest {
                    alias: String::from("use1.edge.example.net"),
                    weight: Some(100),
                    priority: None,
                    geo_scope: None,
                    latency_region: None,
                    health_check: Some(CreateDnsAliasHealthCheckRequest {
                        protocol: String::from("tcp"),
                        path: Some(String::from("/ready")),
                        port: Some(443),
                    }),
                }],
            })
            .await
            .expect_err("tcp health checks may not declare an HTTP path");

        assert!(
            error
                .to_string()
                .contains("tcp health checks may not set a request path")
        );
    }

    #[tokio::test]
    async fn mark_provider_task_delivered_updates_status() {
        let service = DnsService::open(temp_state_root()).await.unwrap();
        service
            .enqueue_cloudflare_task(
                "upsert_record",
                "resource-1",
                serde_json::json!({"hello": "world"}),
            )
            .await
            .unwrap();

        let tasks = service.provider_tasks.list().await.unwrap();
        assert_eq!(tasks.len(), 1);
        let (task_id, task) = tasks.into_iter().next().unwrap();

        let delivered: ProviderSyncTask = response_json(
            service
                .mark_provider_task_delivered(&task_id)
                .await
                .unwrap(),
        )
        .await;

        assert_eq!(delivered.id, task.value.id);
        assert_eq!(delivered.status, "delivered");
        assert_eq!(delivered.last_error, None);
        assert_eq!(delivered.attempt_count, 1);
        assert!(delivered.last_attempt_at.is_some());
        assert_eq!(delivered.next_attempt_at, None);
        let stored = service.provider_tasks.get(&task_id).await.unwrap().unwrap();
        assert_eq!(stored.value.status, "delivered");
        assert_eq!(stored.value.attempt_count, 1);
        assert!(stored.version > task.version);
    }

    #[tokio::test]
    async fn publication_intent_provider_task_can_surface_failed_and_retry_pending_state() {
        let service = DnsService::open(temp_state_root()).await.unwrap();
        let zone: ZoneRecord = response_json(
            service
                .create_zone(CreateZoneRequest {
                    domain: String::from("example.com"),
                })
                .await
                .unwrap(),
        )
        .await;
        let intent: DnsPublicationIntent = response_json(
            service
                .create_publication_intent(CreateDnsPublicationIntentRequest {
                    zone_id: zone.id.to_string(),
                    hostname: String::from("api.example.com"),
                    steering: String::from("weighted"),
                    answers: vec![CreateDnsPublicationAnswerRequest {
                        alias: String::from("use1.edge.example.net"),
                        weight: Some(100),
                        priority: None,
                        geo_scope: None,
                        latency_region: None,
                        health_check: Some(CreateDnsAliasHealthCheckRequest {
                            protocol: String::from("https"),
                            path: None,
                            port: Some(443),
                        }),
                    }],
                })
                .await
                .unwrap(),
        )
        .await;
        let task_id = service
            .provider_tasks
            .list()
            .await
            .unwrap()
            .into_iter()
            .find(|(_, stored)| stored.value.resource_id == intent.id.to_string())
            .map(|(id, _)| id)
            .unwrap_or_else(|| panic!("missing publication intent provider task"));

        let retry_pending: ProviderSyncTask = response_json(
            service
                .mark_provider_task_failed(
                    &task_id,
                    ProviderTaskFailureRequest {
                        error: String::from("upstream rate limit"),
                        retry_after_seconds: Some(120),
                    },
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(retry_pending.status, "retry_pending");
        assert_eq!(
            retry_pending.last_error.as_deref(),
            Some("upstream rate limit")
        );
        assert_eq!(retry_pending.attempt_count, 1);
        assert!(retry_pending.last_attempt_at.is_some());
        assert!(retry_pending.next_attempt_at.is_some());

        let delivery_states = service
            .list_publication_intent_delivery_states()
            .await
            .unwrap();
        assert_eq!(delivery_states.len(), 1);
        assert_eq!(delivery_states[0].publication_intent_id, intent.id);
        assert_eq!(delivery_states[0].status, "retry_pending");
        assert_eq!(delivery_states[0].attempt_count, 1);
        assert_eq!(
            delivery_states[0].last_error.as_deref(),
            Some("upstream rate limit")
        );

        let delivered: ProviderSyncTask = response_json(
            service
                .mark_provider_task_delivered(&task_id)
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(delivered.status, "delivered");
        assert_eq!(delivered.last_error, None);
        assert_eq!(delivered.attempt_count, 2);
        assert_eq!(delivered.next_attempt_at, None);

        let audit_log = fs::read_to_string(service.state_root.join("audit.log"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(audit_log.contains("dns.provider_task.retry_scheduled.v1"));
        assert!(audit_log.contains("dns.provider_task.delivered.v1"));
    }

    #[tokio::test]
    async fn publication_intent_provider_task_can_surface_terminal_failure_state() {
        let service = DnsService::open(temp_state_root()).await.unwrap();
        let zone: ZoneRecord = response_json(
            service
                .create_zone(CreateZoneRequest {
                    domain: String::from("example.com"),
                })
                .await
                .unwrap(),
        )
        .await;
        let intent: DnsPublicationIntent = response_json(
            service
                .create_publication_intent(CreateDnsPublicationIntentRequest {
                    zone_id: zone.id.to_string(),
                    hostname: String::from("failover.example.com"),
                    steering: String::from("priority"),
                    answers: vec![CreateDnsPublicationAnswerRequest {
                        alias: String::from("primary.edge.example.net"),
                        weight: None,
                        priority: Some(10),
                        geo_scope: None,
                        latency_region: None,
                        health_check: None,
                    }],
                })
                .await
                .unwrap(),
        )
        .await;
        let task_id = service
            .provider_tasks
            .list()
            .await
            .unwrap()
            .into_iter()
            .find(|(_, stored)| stored.value.resource_id == intent.id.to_string())
            .map(|(id, _)| id)
            .unwrap_or_else(|| panic!("missing publication intent provider task"));

        let failed: ProviderSyncTask = response_json(
            service
                .mark_provider_task_failed(
                    &task_id,
                    ProviderTaskFailureRequest {
                        error: String::from("provider validation rejected alias"),
                        retry_after_seconds: None,
                    },
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(failed.status, "failed");
        assert_eq!(failed.attempt_count, 1);
        assert_eq!(
            failed.last_error.as_deref(),
            Some("provider validation rejected alias")
        );
        assert_eq!(failed.next_attempt_at, None);

        let summary: serde_json::Value =
            response_json(service.summary_report().await.unwrap()).await;
        let delivery_states = summary["publication_intents"]["delivery_states"]
            .as_array()
            .unwrap_or_else(|| panic!("publication_intents.delivery_states should be an array"));
        let failed_count = delivery_states
            .iter()
            .find(|entry| entry["key"] == "failed")
            .and_then(|entry| entry["count"].as_u64())
            .unwrap_or_default();
        assert_eq!(failed_count, 1);

        let audit_log = fs::read_to_string(service.state_root.join("audit.log"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(audit_log.contains("dns.provider_task.failed.v1"));
    }

    #[tokio::test]
    async fn publication_intent_delivery_routes_surface_retry_and_failed_state() {
        let service = DnsService::open(temp_state_root()).await.unwrap();
        let zone: ZoneRecord = response_json(
            service
                .create_zone(CreateZoneRequest {
                    domain: String::from("example.com"),
                })
                .await
                .unwrap(),
        )
        .await;
        let intent: DnsPublicationIntent = response_json(
            service
                .create_publication_intent(CreateDnsPublicationIntentRequest {
                    zone_id: zone.id.to_string(),
                    hostname: String::from("api.example.com"),
                    steering: String::from("weighted"),
                    answers: vec![CreateDnsPublicationAnswerRequest {
                        alias: String::from("use1.edge.example.net"),
                        weight: Some(100),
                        priority: None,
                        geo_scope: None,
                        latency_region: None,
                        health_check: None,
                    }],
                })
                .await
                .unwrap(),
        )
        .await;
        let task_id = service
            .provider_tasks
            .list()
            .await
            .unwrap()
            .into_iter()
            .find(|(_, stored)| stored.value.resource_id == intent.id.to_string())
            .map(|(id, _)| id)
            .unwrap_or_else(|| panic!("missing publication intent provider task"));

        let retry_body =
            serde_json::json!({"error": "upstream rate limit", "retry_after_seconds": 30})
                .to_string();
        let retry_pending: ProviderSyncTask = response_json(
            dispatch_request(
                &service,
                "POST",
                &format!("/dns/provider-tasks/{task_id}/fail"),
                Some(retry_body.as_str()),
            )
            .await,
        )
        .await;
        assert_eq!(retry_pending.status, "retry_pending");
        assert_eq!(retry_pending.attempt_count, 1);
        assert_eq!(
            retry_pending.last_error.as_deref(),
            Some("upstream rate limit")
        );
        assert!(retry_pending.next_attempt_at.is_some());

        let delivery_states: Vec<DnsPublicationIntentDeliveryState> = response_json(
            dispatch_request(&service, "GET", "/dns/publication-intents/delivery", None).await,
        )
        .await;
        assert_eq!(delivery_states.len(), 1);
        assert_eq!(delivery_states[0].publication_intent_id, intent.id);
        assert_eq!(delivery_states[0].provider_task_id, retry_pending.id);
        assert_eq!(delivery_states[0].status, "retry_pending");
        assert_eq!(delivery_states[0].attempt_count, 1);

        let failed_body =
            serde_json::json!({"error": "provider validation rejected alias"}).to_string();
        let failed: ProviderSyncTask = response_json(
            dispatch_request(
                &service,
                "POST",
                &format!("/dns/provider-tasks/{task_id}/fail"),
                Some(failed_body.as_str()),
            )
            .await,
        )
        .await;
        assert_eq!(failed.status, "failed");
        assert_eq!(failed.attempt_count, 2);
        assert_eq!(failed.next_attempt_at, None);
        assert_eq!(
            failed.last_error.as_deref(),
            Some("provider validation rejected alias")
        );

        let delivery_states: Vec<DnsPublicationIntentDeliveryState> = response_json(
            dispatch_request(&service, "GET", "/dns/publication-intents/delivery", None).await,
        )
        .await;
        assert_eq!(delivery_states.len(), 1);
        assert_eq!(delivery_states[0].status, "failed");
        assert_eq!(delivery_states[0].attempt_count, 2);
        assert_eq!(
            delivery_states[0].last_error.as_deref(),
            Some("provider validation rejected alias")
        );
        assert_eq!(delivery_states[0].next_attempt_at, None);
    }

    #[tokio::test]
    async fn dns_mutations_append_durable_audit_and_outbox_events() {
        let service = DnsService::open(temp_state_root())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let zone: ZoneRecord = response_json(
            service
                .create_zone(CreateZoneRequest {
                    domain: String::from("audit.example"),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let _record: DnsRecord = response_json(
            service
                .create_record(CreateRecordRequest {
                    zone_id: zone.id.to_string(),
                    name: String::from("www"),
                    record_type: String::from("A"),
                    value: String::from("192.0.2.50"),
                    ttl: 300,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let _intent: DnsPublicationIntent = response_json(
            service
                .create_publication_intent(CreateDnsPublicationIntentRequest {
                    zone_id: zone.id.to_string(),
                    hostname: String::from("api.audit.example"),
                    steering: String::from("weighted"),
                    answers: vec![CreateDnsPublicationAnswerRequest {
                        alias: String::from("use1.edge.example.net"),
                        weight: Some(100),
                        priority: None,
                        geo_scope: None,
                        latency_region: None,
                        health_check: None,
                    }],
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let _verified_zone: ZoneRecord = response_json(
            service
                .verify_zone(zone.id.as_str())
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let deliver_task_id = service
            .provider_tasks
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(id, _)| id.clone())
            .unwrap_or_else(|| panic!("missing provider task"));
        let _delivered_task: ProviderSyncTask = response_json(
            service
                .mark_provider_task_delivered(&deliver_task_id)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let messages = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(messages.len(), 5);
        let event_types = messages
            .iter()
            .map(|message| message.payload.header.event_type.clone())
            .collect::<Vec<_>>();
        assert!(event_types.contains(&String::from("dns.zone.created.v1")));
        assert!(event_types.contains(&String::from("dns.record.created.v1")));
        assert!(event_types.contains(&String::from("dns.publication_intent.created.v1")));
        assert!(event_types.contains(&String::from("dns.zone.verified.v1")));
        assert!(event_types.contains(&String::from("dns.provider_task.delivered.v1")));

        let audit_log = fs::read_to_string(service.state_root.join("audit.log"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(audit_log.contains("dns.zone.created.v1"));
        assert!(audit_log.contains("dns.record.created.v1"));
        assert!(audit_log.contains("dns.publication_intent.created.v1"));
        assert!(audit_log.contains("dns.zone.verified.v1"));
        assert!(audit_log.contains("dns.provider_task.delivered.v1"));
    }

    #[tokio::test]
    async fn summary_report_reflects_persisted_zone_record_and_task_state() {
        let service = DnsService::open(temp_state_root())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let zone_alpha: ZoneRecord = response_json(
            service
                .create_zone(CreateZoneRequest {
                    domain: String::from("alpha.example"),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let _zone_beta: ZoneRecord = response_json(
            service
                .create_zone(CreateZoneRequest {
                    domain: String::from("beta.example"),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let _verified_alpha: ZoneRecord = response_json(
            service
                .verify_zone(zone_alpha.id.as_str())
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let record_a: DnsRecord = response_json(
            service
                .create_record(CreateRecordRequest {
                    zone_id: zone_alpha.id.to_string(),
                    name: String::from("www"),
                    record_type: String::from("a"),
                    value: String::from("192.0.2.10"),
                    ttl: 300,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let _record_txt: DnsRecord = response_json(
            service
                .create_record(CreateRecordRequest {
                    zone_id: zone_alpha.id.to_string(),
                    name: String::from("@"),
                    record_type: String::from("TXT"),
                    value: String::from("v=spf1 -all"),
                    ttl: 300,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        service
            .records
            .soft_delete(record_a.id.as_str(), Some(1))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let task_id = service
            .provider_tasks
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(id, _)| id.clone())
            .unwrap_or_else(|| panic!("missing provider task"));
        let _delivered: ProviderSyncTask = response_json(
            service
                .mark_provider_task_delivered(task_id.as_str())
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let summary: serde_json::Value = response_json(
            service
                .summary_report()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        assert_eq!(summary["zones"]["total"], 2);
        assert_eq!(summary["zones"]["verified"], 1);
        assert_eq!(summary["zones"]["unverified"], 1);
        assert_eq!(summary["records"]["total"], 1);
        assert_eq!(summary["publication_intents"]["total"], 0);
        assert_eq!(summary["provider_tasks"]["total"], 4);

        let by_type = summary["records"]["by_type"]
            .as_array()
            .unwrap_or_else(|| panic!("records.by_type should be an array"));
        let txt_count = by_type
            .iter()
            .find(|entry| entry["key"] == "TXT")
            .and_then(|entry| entry["count"].as_u64())
            .unwrap_or_default();
        assert_eq!(txt_count, 1);

        let by_status = summary["provider_tasks"]["by_status"]
            .as_array()
            .unwrap_or_else(|| panic!("provider_tasks.by_status should be an array"));
        let delivered = by_status
            .iter()
            .find(|entry| entry["key"] == "delivered")
            .and_then(|entry| entry["count"].as_u64())
            .unwrap_or_default();
        let pending = by_status
            .iter()
            .find(|entry| entry["key"] == "pending")
            .and_then(|entry| entry["count"].as_u64())
            .unwrap_or_default();
        assert_eq!(delivered, 1);
        assert_eq!(pending, 3);
    }

    #[tokio::test]
    async fn summary_report_counts_publication_intents_and_health_checked_answers() {
        let service = DnsService::open(temp_state_root()).await.unwrap();
        let zone: ZoneRecord = response_json(
            service
                .create_zone(CreateZoneRequest {
                    domain: String::from("example.com"),
                })
                .await
                .unwrap(),
        )
        .await;

        let _weighted: DnsPublicationIntent = response_json(
            service
                .create_publication_intent(CreateDnsPublicationIntentRequest {
                    zone_id: zone.id.to_string(),
                    hostname: String::from("api.example.com"),
                    steering: String::from("weighted"),
                    answers: vec![CreateDnsPublicationAnswerRequest {
                        alias: String::from("use1.edge.example.net"),
                        weight: Some(100),
                        priority: None,
                        geo_scope: None,
                        latency_region: None,
                        health_check: Some(CreateDnsAliasHealthCheckRequest {
                            protocol: String::from("https"),
                            path: Some(String::from("/ready")),
                            port: Some(443),
                        }),
                    }],
                })
                .await
                .unwrap(),
        )
        .await;
        let _geo: DnsPublicationIntent = response_json(
            service
                .create_publication_intent(CreateDnsPublicationIntentRequest {
                    zone_id: zone.id.to_string(),
                    hostname: String::from("geo.example.com"),
                    steering: String::from("geo"),
                    answers: vec![CreateDnsPublicationAnswerRequest {
                        alias: String::from("eu.edge.example.net"),
                        weight: None,
                        priority: None,
                        geo_scope: Some(String::from("region/eu")),
                        latency_region: None,
                        health_check: None,
                    }],
                })
                .await
                .unwrap(),
        )
        .await;

        let summary: serde_json::Value =
            response_json(service.summary_report().await.unwrap()).await;
        assert_eq!(summary["publication_intents"]["total"], 2);
        assert_eq!(summary["publication_intents"]["health_checked_answers"], 1);
        let by_steering = summary["publication_intents"]["by_steering"]
            .as_array()
            .unwrap_or_else(|| panic!("publication_intents.by_steering should be an array"));
        let weighted = by_steering
            .iter()
            .find(|entry| entry["key"] == "weighted")
            .and_then(|entry| entry["count"].as_u64())
            .unwrap_or_default();
        let pending_delivery = summary["publication_intents"]["delivery_states"]
            .as_array()
            .unwrap_or_else(|| panic!("publication_intents.delivery_states should be an array"))
            .iter()
            .find(|entry| entry["key"] == "pending")
            .and_then(|entry| entry["count"].as_u64())
            .unwrap_or_default();
        let geo = by_steering
            .iter()
            .find(|entry| entry["key"] == "geo")
            .and_then(|entry| entry["count"].as_u64())
            .unwrap_or_default();
        assert_eq!(weighted, 1);
        assert_eq!(geo, 1);
        assert_eq!(pending_delivery, 2);
    }

    #[test]
    fn collect_active_values_skips_deleted_entries_and_deduplicates_by_key() {
        let records = vec![
            (
                String::from("b"),
                uhost_store::StoredDocument {
                    version: 1,
                    updated_at: OffsetDateTime::now_utc(),
                    deleted: false,
                    value: 1_u32,
                },
            ),
            (
                String::from("a"),
                uhost_store::StoredDocument {
                    version: 1,
                    updated_at: OffsetDateTime::now_utc(),
                    deleted: false,
                    value: 2_u32,
                },
            ),
            (
                String::from("a"),
                uhost_store::StoredDocument {
                    version: 2,
                    updated_at: OffsetDateTime::now_utc(),
                    deleted: false,
                    value: 3_u32,
                },
            ),
            (
                String::from("c"),
                uhost_store::StoredDocument {
                    version: 1,
                    updated_at: OffsetDateTime::now_utc(),
                    deleted: true,
                    value: 4_u32,
                },
            ),
        ];

        assert_eq!(collect_active_values(records), vec![3, 1]);
    }
}
