//! Notifications and communications service.
//!
//! This bounded context owns:
//! - webhook endpoint registration and secret rotation
//! - notification template and localization records
//! - per-subject delivery preferences
//! - queued delivery state machine with retry/backoff
//! - dead-letter capture and replay
//!
//! The implementation is file-backed and deterministic for all-in-one mode while
//! keeping explicit contracts that can be lifted to external transports.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use http::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{PlatformError, RequestContext, Result, hmac_sha256, sha256_hex};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{AuditLog, DocumentStore, DurableOutbox};
use uhost_types::{
    AlertRuleId, AuditActor, AuditId, DeadLetterId, EventHeader, EventPayload, NotificationId,
    NotificationPreferenceId, NotificationTemplateId, OwnershipScope, PlatformEvent,
    ResourceMetadata, ServiceEvent, WebhookEndpointId,
};

/// Delivery state for one notification message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    /// Waiting for dispatch.
    Queued,
    /// Dispatch worker is processing this message.
    Delivering,
    /// Dispatch succeeded.
    Delivered,
    /// Dispatch failed and is eligible for retry.
    Failed,
    /// Suppressed by preference policy before dispatch.
    Suppressed,
    /// Retry budget exhausted and message was moved to dead letters.
    DeadLettered,
}

/// Per-message history event kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationHistoryEventKind {
    /// Message entered the queue.
    Queued,
    /// Message was suppressed by preferences.
    Suppressed,
    /// Delivery succeeded.
    Delivered,
    /// Delivery failed but remains retryable.
    Failed,
    /// Retry budget exhausted.
    DeadLettered,
    /// Message was manually requeued.
    Requeued,
    /// Operator or automation acknowledged the notification.
    Acknowledged,
    /// Message escalation workflow was snoozed.
    Snoozed,
    /// Message was escalated to a follow-up notification.
    Escalated,
}

/// Durable per-message workflow history entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationHistoryEntry {
    /// Monotonic sequence number within one notification history.
    pub sequence: u32,
    /// Event kind.
    pub event: NotificationHistoryEventKind,
    /// Event time.
    pub occurred_at: OffsetDateTime,
    /// Actor responsible for the event.
    pub actor: String,
    /// Delivery state at the time of the event.
    pub state: DeliveryState,
    /// Attempts consumed when the event happened.
    pub attempts: u32,
    /// Optional human-readable detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Optional case link carried through the workflow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_reference: Option<String>,
    /// Optional related notification id for escalation hops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_notification_id: Option<NotificationId>,
}

/// Durable webhook endpoint configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookEndpointRecord {
    /// Endpoint identifier.
    pub id: WebhookEndpointId,
    /// Operator-visible endpoint name.
    pub name: String,
    /// Target URL.
    pub url: String,
    /// Hash of endpoint signing secret.
    pub signing_secret_hash: String,
    /// Whether endpoint is active.
    pub enabled: bool,
    /// Maximum attempts before dead-lettering.
    pub max_attempts: u32,
    /// Dispatch timeout hint in milliseconds.
    pub timeout_ms: u32,
    /// Exponential retry base in seconds.
    pub backoff_base_seconds: u32,
    /// Last endpoint error if present.
    pub last_error: Option<String>,
    /// Update timestamp.
    pub updated_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Localized notification template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationTemplateRecord {
    /// Template identifier.
    pub id: NotificationTemplateId,
    /// Template name.
    pub name: String,
    /// Target channel.
    pub channel: String,
    /// Locale tag.
    pub locale: String,
    /// Subject template.
    pub subject_template: String,
    /// Body template.
    pub body_template: String,
    /// Whether template is active.
    pub enabled: bool,
    /// Incrementing template version.
    pub version: u32,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Per-subject preference model for one channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationPreferenceRecord {
    /// Preference identifier.
    pub id: NotificationPreferenceId,
    /// Subject key (`tenant:<id>`, `user:<id>`, etc.).
    pub subject_key: String,
    /// Channel.
    pub channel: String,
    /// Whether delivery is enabled.
    pub enabled: bool,
    /// Delivery mode (`immediate`, `hourly`, `daily`, `muted`).
    pub digest_mode: String,
    /// Preferred locale.
    pub locale: String,
    /// Last update timestamp.
    pub updated_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// One queued notification message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationRecord {
    /// Message identifier.
    pub id: NotificationId,
    /// Channel (`email`, `sms`, `in_app`, `webhook`, etc.).
    pub channel: String,
    /// Destination address or endpoint key.
    pub destination: String,
    /// Subject line.
    pub subject: String,
    /// Body payload.
    pub body: String,
    /// Source template when rendered from template.
    pub template_id: Option<NotificationTemplateId>,
    /// Subject key used for preference checks.
    pub subject_key: Option<String>,
    /// Optional support/governance case link carried with this notification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_reference: Option<String>,
    /// Locale used for rendering/delivery.
    pub locale: String,
    /// Optional webhook endpoint binding for webhook channels.
    pub webhook_endpoint_id: Option<WebhookEndpointId>,
    /// Current state.
    pub state: DeliveryState,
    /// Attempt counter.
    pub attempts: u32,
    /// Retry budget ceiling.
    pub max_attempts: u32,
    /// Earliest next attempt.
    pub next_attempt_at: Option<OffsetDateTime>,
    /// Last error.
    pub last_error: Option<String>,
    /// When this message was acknowledged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged_at: Option<OffsetDateTime>,
    /// Actor that acknowledged this message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged_by: Option<String>,
    /// Optional acknowledgement note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledgement_note: Option<String>,
    /// When escalation handling is snoozed until.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snoozed_until: Option<OffsetDateTime>,
    /// Actor that applied the active snooze.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snoozed_by: Option<String>,
    /// Optional snooze reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snooze_reason: Option<String>,
    /// Escalation hop count for this message.
    #[serde(default)]
    pub escalation_count: u32,
    /// Last escalation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_escalated_at: Option<OffsetDateTime>,
    /// Actor responsible for the last escalation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_escalated_by: Option<String>,
    /// Last follow-up notification created by escalation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_escalated_notification_id: Option<NotificationId>,
    /// Signature derived from canonical payload.
    pub signature: String,
    /// Created timestamp.
    pub created_at: OffsetDateTime,
    /// Last update timestamp.
    pub updated_at: OffsetDateTime,
    /// Durable per-message workflow history.
    #[serde(default)]
    pub history: Vec<NotificationHistoryEntry>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Dead-letter capture for notifications that exhausted retries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationDeadLetterRecord {
    /// Dead-letter identifier.
    pub id: DeadLetterId,
    /// Original notification id.
    pub notification_id: NotificationId,
    /// Channel.
    pub channel: String,
    /// Destination.
    pub destination: String,
    /// Attempts consumed before dead-lettering.
    pub attempts: u32,
    /// Last error.
    pub last_error: String,
    /// Capture time.
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

/// Alert route used to fan out incident/alert notifications to operator channels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRouteRecord {
    /// Alert route identifier.
    pub id: AlertRuleId,
    /// Operator-visible route name.
    pub name: String,
    /// Minimum severity accepted by this route (`info`, `warning`, `error`, `critical`).
    pub min_severity: String,
    /// Destination channel used for routed alerts.
    pub channel: String,
    /// Delivery destination for routed alerts.
    pub destination: String,
    /// Optional subject key for preference checks and tenant-specific routing.
    pub subject_key: Option<String>,
    /// Optional webhook endpoint binding for webhook channels.
    pub webhook_endpoint_id: Option<WebhookEndpointId>,
    /// Cooldown window between repeated alert deliveries.
    pub cooldown_seconds: u32,
    /// Whether this route is active.
    pub enabled: bool,
    /// Last trigger timestamp.
    pub last_triggered_at: Option<OffsetDateTime>,
    /// Last dedupe key associated with this route trigger.
    pub last_dedupe_key: Option<String>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Summary of one dispatch sweep operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchSummary {
    /// Number of messages inspected.
    pub inspected: usize,
    /// Number delivered.
    pub delivered: usize,
    /// Number failed (retryable).
    pub failed: usize,
    /// Number suppressed.
    pub suppressed: usize,
    /// Number dead-lettered.
    pub dead_lettered: usize,
    /// Number skipped as not yet due.
    pub skipped_not_due: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateWebhookEndpointRequest {
    name: String,
    url: String,
    signing_secret: String,
    enabled: Option<bool>,
    max_attempts: Option<u32>,
    timeout_ms: Option<u32>,
    backoff_base_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RotateWebhookSecretRequest {
    signing_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateTemplateRequest {
    name: String,
    channel: String,
    locale: String,
    subject_template: String,
    body_template: String,
    enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreatePreferenceRequest {
    subject_key: String,
    channel: String,
    enabled: bool,
    digest_mode: Option<String>,
    locale: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateNotificationRequest {
    channel: String,
    destination: String,
    subject: String,
    body: String,
    template_id: Option<String>,
    template_vars: Option<BTreeMap<String, String>>,
    subject_key: Option<String>,
    case_reference: Option<String>,
    locale: Option<String>,
    webhook_endpoint_id: Option<String>,
    max_attempts: Option<u32>,
    deliver_after_seconds: Option<u32>,
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
struct AcknowledgeNotificationRequest {
    note: Option<String>,
    case_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnoozeNotificationRequest {
    snooze_seconds: Option<u32>,
    reason: Option<String>,
    case_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EscalateNotificationRequest {
    channel: String,
    destination: String,
    subject: Option<String>,
    body: Option<String>,
    subject_key: Option<String>,
    case_reference: Option<String>,
    locale: Option<String>,
    webhook_endpoint_id: Option<String>,
    max_attempts: Option<u32>,
    deliver_after_seconds: Option<u32>,
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
struct CreateAlertRouteRequest {
    name: String,
    min_severity: String,
    channel: String,
    destination: String,
    subject_key: Option<String>,
    webhook_endpoint_id: Option<String>,
    cooldown_seconds: Option<u32>,
    enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TriggerAlertRequest {
    severity: String,
    title: String,
    body: String,
    subject_key: Option<String>,
    case_reference: Option<String>,
    dedupe_key: Option<String>,
    labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TriggerAlertSummary {
    severity: String,
    routed: usize,
    suppressed_by_cooldown: usize,
    route_ids: Vec<String>,
    notification_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NotifySummaryCounter {
    key: String,
    count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NotifySummary {
    webhook_endpoints: NotifyEndpointSummary,
    templates: NotifyTemplateSummary,
    preferences: NotifyPreferenceSummary,
    alert_routes: NotifyAlertRouteSummary,
    notifications: NotifyNotificationSummary,
    dead_letters: NotifyDeadLetterSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NotifyEndpointSummary {
    total: usize,
    enabled: usize,
    disabled: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NotifyTemplateSummary {
    total: usize,
    enabled: usize,
    disabled: usize,
    by_channel: Vec<NotifySummaryCounter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NotifyPreferenceSummary {
    total: usize,
    enabled: usize,
    disabled: usize,
    muted: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NotifyAlertRouteSummary {
    total: usize,
    enabled: usize,
    disabled: usize,
    by_channel: Vec<NotifySummaryCounter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NotifyNotificationSummary {
    total: usize,
    pending: usize,
    sent: usize,
    failed: usize,
    suppressed: usize,
    dead_lettered: usize,
    by_state: Vec<NotifySummaryCounter>,
    by_channel: Vec<NotifySummaryCounter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NotifyDeadLetterSummary {
    total: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NotificationHistoryResponse {
    notification_id: NotificationId,
    case_reference: Option<String>,
    acknowledged_at: Option<OffsetDateTime>,
    acknowledged_by: Option<String>,
    snoozed_until: Option<OffsetDateTime>,
    escalation_count: u32,
    last_escalated_notification_id: Option<NotificationId>,
    history: Vec<NotificationHistoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SupportCaseLinkRecord {
    id: String,
    #[serde(default)]
    notify_message_ids: Vec<String>,
    updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchOutcome {
    Delivered,
    FailedRetryable,
    Suppressed,
    DeadLettered,
}

/// Notify service implementation.
#[derive(Debug, Clone)]
pub struct NotifyService {
    webhook_endpoints: DocumentStore<WebhookEndpointRecord>,
    templates: DocumentStore<NotificationTemplateRecord>,
    preferences: DocumentStore<NotificationPreferenceRecord>,
    alert_routes: DocumentStore<AlertRouteRecord>,
    notifications: DocumentStore<NotificationRecord>,
    dead_letters: DocumentStore<NotificationDeadLetterRecord>,
    support_cases: DocumentStore<SupportCaseLinkRecord>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    signing_key: Vec<u8>,
    state_root: PathBuf,
}

impl NotifyService {
    /// Open notify state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let platform_root = state_root.as_ref();
        let root = state_root.as_ref().join("notify");
        Ok(Self {
            webhook_endpoints: DocumentStore::open(root.join("webhook_endpoints.json")).await?,
            templates: DocumentStore::open(root.join("templates.json")).await?,
            preferences: DocumentStore::open(root.join("preferences.json")).await?,
            alert_routes: DocumentStore::open(root.join("alert_routes.json")).await?,
            notifications: DocumentStore::open(root.join("notifications.json")).await?,
            dead_letters: DocumentStore::open(root.join("dead_letters.json")).await?,
            support_cases: DocumentStore::open(platform_root.join("abuse/support_cases.json"))
                .await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            signing_key: b"uhost-notify-signing-key-material".to_vec(),
            state_root: root,
        })
    }

    async fn support_case_id_for_notification(
        &self,
        record: &NotificationRecord,
    ) -> Option<String> {
        let support_cases = self.support_cases.list().await.ok()?;
        let mut selected: Option<(String, OffsetDateTime)> = None;

        for (_, stored) in support_cases {
            if stored.deleted {
                continue;
            }

            let support_case = stored.value;
            let matches_notification = support_case
                .notify_message_ids
                .iter()
                .any(|notification_id| notification_id == record.id.as_str());
            let matches_case_reference = record
                .case_reference
                .as_deref()
                .is_some_and(|case_reference| case_reference == support_case.id);
            if !(matches_notification || matches_case_reference) {
                continue;
            }

            if selected
                .as_ref()
                .is_none_or(|(_, updated_at)| support_case.updated_at >= *updated_at)
            {
                selected = Some((support_case.id, support_case.updated_at));
            }
        }

        selected
            .map(|(id, _)| id)
            .or_else(|| record.case_reference.clone())
    }

    async fn consumer_notification_record(
        &self,
        mut record: NotificationRecord,
    ) -> NotificationRecord {
        record.case_reference = self.support_case_id_for_notification(&record).await;
        record
    }

    async fn consumer_notification_response(
        &self,
        status: StatusCode,
        record: NotificationRecord,
    ) -> Result<http::Response<ApiBody>> {
        let record = self.consumer_notification_record(record).await;
        json_response(status, &record)
    }

    async fn consumer_notification_history(
        &self,
        record: NotificationRecord,
    ) -> NotificationHistoryResponse {
        let case_reference = self.support_case_id_for_notification(&record).await;
        let history = record
            .history
            .into_iter()
            .map(|mut entry| {
                if case_reference.is_some() && entry.case_reference.is_some() {
                    entry.case_reference = case_reference.clone();
                }
                entry
            })
            .collect();

        NotificationHistoryResponse {
            notification_id: record.id,
            case_reference,
            acknowledged_at: record.acknowledged_at,
            acknowledged_by: record.acknowledged_by,
            snoozed_until: record.snoozed_until,
            escalation_count: record.escalation_count,
            last_escalated_notification_id: record.last_escalated_notification_id,
            history,
        }
    }

    async fn create_webhook_endpoint(
        &self,
        request: CreateWebhookEndpointRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        if request.name.trim().is_empty() {
            return Err(PlatformError::invalid("name may not be empty"));
        }
        if request.signing_secret.trim().is_empty() {
            return Err(PlatformError::invalid("signing_secret may not be empty"));
        }
        let url = normalize_webhook_url(&request.url)?;
        let id = WebhookEndpointId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate webhook endpoint id")
                .with_detail(error.to_string())
        })?;
        let record = WebhookEndpointRecord {
            id: id.clone(),
            name: request.name.trim().to_owned(),
            url,
            signing_secret_hash: sha256_hex(request.signing_secret.as_bytes()),
            enabled: request.enabled.unwrap_or(true),
            max_attempts: request.max_attempts.unwrap_or(5).clamp(1, 20),
            timeout_ms: request.timeout_ms.unwrap_or(10_000).clamp(500, 120_000),
            backoff_base_seconds: request.backoff_base_seconds.unwrap_or(30).clamp(1, 3600),
            last_error: None,
            updated_at: OffsetDateTime::now_utc(),
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.webhook_endpoints
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "notify.webhook_endpoint.created.v1",
            "notify_webhook_endpoint",
            id.as_str(),
            "created",
            serde_json::json!({
                "enabled": record.enabled,
                "max_attempts": record.max_attempts,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn rotate_webhook_secret(
        &self,
        webhook_endpoint_id: &str,
        request: RotateWebhookSecretRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        if request.signing_secret.trim().is_empty() {
            return Err(PlatformError::invalid("signing_secret may not be empty"));
        }
        let endpoint_id =
            WebhookEndpointId::parse(webhook_endpoint_id.to_owned()).map_err(|error| {
                PlatformError::invalid("invalid webhook endpoint id").with_detail(error.to_string())
            })?;
        let stored = self
            .webhook_endpoints
            .get(endpoint_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("webhook endpoint does not exist"))?;
        let mut record = stored.value;
        record.signing_secret_hash = sha256_hex(request.signing_secret.as_bytes());
        record.updated_at = OffsetDateTime::now_utc();
        record
            .metadata
            .touch(sha256_hex(endpoint_id.as_str().as_bytes()));
        self.webhook_endpoints
            .upsert(endpoint_id.as_str(), record.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "notify.webhook_endpoint.secret_rotated.v1",
            "notify_webhook_endpoint",
            endpoint_id.as_str(),
            "secret_rotated",
            serde_json::json!({}),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn create_template(
        &self,
        request: CreateTemplateRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        if request.name.trim().is_empty() {
            return Err(PlatformError::invalid("name may not be empty"));
        }
        let channel = normalize_channel(&request.channel)?;
        let locale = normalize_locale(&request.locale)?;
        if request.subject_template.trim().is_empty() || request.body_template.trim().is_empty() {
            return Err(PlatformError::invalid(
                "subject_template and body_template may not be empty",
            ));
        }
        let id = NotificationTemplateId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate notification template id")
                .with_detail(error.to_string())
        })?;
        let record = NotificationTemplateRecord {
            id: id.clone(),
            name: request.name.trim().to_owned(),
            channel,
            locale,
            subject_template: request.subject_template,
            body_template: request.body_template,
            enabled: request.enabled.unwrap_or(true),
            version: 1,
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.templates.create(id.as_str(), record.clone()).await?;
        self.append_event(
            "notify.template.created.v1",
            "notify_template",
            id.as_str(),
            "created",
            serde_json::json!({
                "channel": record.channel,
                "locale": record.locale,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn upsert_preference(
        &self,
        request: CreatePreferenceRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let subject_key = normalize_subject_key(&request.subject_key)?;
        let channel = normalize_channel(&request.channel)?;
        let digest_mode =
            normalize_digest_mode(request.digest_mode.as_deref().unwrap_or("immediate"))?;
        let locale = normalize_locale(request.locale.as_deref().unwrap_or("en-us"))?;
        let key = preference_lookup_key(&subject_key, &channel);
        let existing = self.preferences.get(&key).await?;
        let id = if let Some(stored) = &existing {
            stored.value.id.clone()
        } else {
            NotificationPreferenceId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate notification preference id")
                    .with_detail(error.to_string())
            })?
        };
        let metadata = existing
            .as_ref()
            .map(|stored| {
                let mut metadata = stored.value.metadata.clone();
                metadata.touch(sha256_hex(key.as_bytes()));
                metadata
            })
            .unwrap_or_else(|| {
                ResourceMetadata::new(
                    OwnershipScope::Tenant,
                    Some(id.to_string()),
                    sha256_hex(key.as_bytes()),
                )
            });
        let record = NotificationPreferenceRecord {
            id,
            subject_key: subject_key.clone(),
            channel: channel.clone(),
            enabled: request.enabled,
            digest_mode,
            locale,
            updated_at: OffsetDateTime::now_utc(),
            metadata,
        };
        self.preferences
            .upsert(&key, record.clone(), existing.map(|stored| stored.version))
            .await?;
        self.append_event(
            "notify.preference.updated.v1",
            "notify_preference",
            &key,
            "updated",
            serde_json::json!({
                "enabled": record.enabled,
                "digest_mode": record.digest_mode,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn create_alert_route(
        &self,
        request: CreateAlertRouteRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        if request.name.trim().is_empty() {
            return Err(PlatformError::invalid("name may not be empty"));
        }
        let min_severity = normalize_alert_severity(&request.min_severity)?;
        let channel = normalize_channel(&request.channel)?;
        if request.destination.trim().is_empty() {
            return Err(PlatformError::invalid("destination may not be empty"));
        }
        let destination = request.destination.trim().to_owned();
        let subject_key = request
            .subject_key
            .as_deref()
            .map(normalize_subject_key)
            .transpose()?;
        let webhook_endpoint_id = request
            .webhook_endpoint_id
            .map(|raw| {
                WebhookEndpointId::parse(raw).map_err(|error| {
                    PlatformError::invalid("invalid webhook_endpoint_id")
                        .with_detail(error.to_string())
                })
            })
            .transpose()?;
        if channel == "webhook" && webhook_endpoint_id.is_none() {
            return Err(PlatformError::invalid(
                "webhook alert routes require webhook_endpoint_id",
            ));
        }
        if channel != "webhook" && webhook_endpoint_id.is_some() {
            return Err(PlatformError::invalid(
                "webhook_endpoint_id is only valid for webhook alert routes",
            ));
        }
        if let Some(endpoint_id) = webhook_endpoint_id.as_ref() {
            let _ = self
                .webhook_endpoints
                .get(endpoint_id.as_str())
                .await?
                .ok_or_else(|| PlatformError::not_found("webhook endpoint does not exist"))?;
        }

        let id = AlertRuleId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate alert route id")
                .with_detail(error.to_string())
        })?;
        let record = AlertRouteRecord {
            id: id.clone(),
            name: request.name.trim().to_owned(),
            min_severity,
            channel,
            destination,
            subject_key,
            webhook_endpoint_id,
            cooldown_seconds: request.cooldown_seconds.unwrap_or(300).clamp(1, 86_400),
            enabled: request.enabled.unwrap_or(true),
            last_triggered_at: None,
            last_dedupe_key: None,
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.alert_routes
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "notify.alert_route.created.v1",
            "notify_alert_route",
            id.as_str(),
            "created",
            serde_json::json!({
                "min_severity": record.min_severity,
                "channel": record.channel,
                "enabled": record.enabled,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn trigger_alert(
        &self,
        request: TriggerAlertRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let severity = normalize_alert_severity(&request.severity)?;
        if request.title.trim().is_empty() {
            return Err(PlatformError::invalid("title may not be empty"));
        }
        if request.body.trim().is_empty() {
            return Err(PlatformError::invalid("body may not be empty"));
        }
        let subject_key = request
            .subject_key
            .as_deref()
            .map(normalize_subject_key)
            .transpose()?;
        let case_reference = request
            .case_reference
            .as_deref()
            .map(normalize_case_reference)
            .transpose()?;
        let dedupe_key = request
            .dedupe_key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let label_payload = if request.labels.is_empty() {
            String::new()
        } else {
            let rendered = request
                .labels
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join("\n");
            format!("\n\nlabels:\n{rendered}")
        };
        let subject = format!(
            "[{}] {}",
            severity.to_ascii_uppercase(),
            request.title.trim()
        );
        let body = format!("{}{}", request.body.trim(), label_payload);
        let now = OffsetDateTime::now_utc();

        let mut routed = 0_usize;
        let mut suppressed_by_cooldown = 0_usize;
        let mut route_ids = Vec::new();
        let mut notification_ids = Vec::new();

        let routes = self.alert_routes.list().await?;
        for (_key, stored) in routes.into_iter().filter(|(_, stored)| !stored.deleted) {
            let mut route = stored.value;
            if !route.enabled {
                continue;
            }
            if severity_rank(&severity) < severity_rank(&route.min_severity) {
                continue;
            }
            if let Some(key) = dedupe_key.as_deref()
                && route
                    .last_dedupe_key
                    .as_deref()
                    .is_some_and(|value| value == key)
                && route.last_triggered_at.is_some_and(|time| {
                    now < time + Duration::seconds(i64::from(route.cooldown_seconds))
                })
            {
                suppressed_by_cooldown = suppressed_by_cooldown.saturating_add(1);
                continue;
            }

            let notification = self
                .build_notification_record(CreateNotificationRequest {
                    channel: route.channel.clone(),
                    destination: route.destination.clone(),
                    subject: subject.clone(),
                    body: body.clone(),
                    template_id: None,
                    template_vars: None,
                    subject_key: subject_key.clone().or_else(|| route.subject_key.clone()),
                    case_reference: case_reference.clone(),
                    locale: Some(String::from("en-us")),
                    webhook_endpoint_id: route
                        .webhook_endpoint_id
                        .as_ref()
                        .map(ToString::to_string),
                    max_attempts: None,
                    deliver_after_seconds: None,
                })
                .await?;
            let notification = self.persist_notification(notification, context).await?;

            route.last_triggered_at = Some(now);
            route.last_dedupe_key = dedupe_key.clone();
            route
                .metadata
                .touch(sha256_hex(route.id.as_str().as_bytes()));
            self.alert_routes
                .upsert(route.id.as_str(), route.clone(), Some(stored.version))
                .await?;

            routed = routed.saturating_add(1);
            route_ids.push(route.id.to_string());
            notification_ids.push(notification.id.to_string());

            self.append_event(
                "notify.alert.route_triggered.v1",
                "notify_alert_route",
                route.id.as_str(),
                "triggered",
                serde_json::json!({
                    "severity": severity,
                    "notification_id": notification.id,
                }),
                context,
            )
            .await?;
        }

        let summary = TriggerAlertSummary {
            severity,
            routed,
            suppressed_by_cooldown,
            route_ids,
            notification_ids,
        };
        self.append_event(
            "notify.alert.triggered.v1",
            "notify_alert",
            dedupe_key.as_deref().unwrap_or("no_dedupe"),
            "triggered",
            serde_json::json!({
                "severity": summary.severity,
                "routed": summary.routed,
                "suppressed_by_cooldown": summary.suppressed_by_cooldown,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &summary)
    }

    async fn create_notification(
        &self,
        request: CreateNotificationRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let record = self.build_notification_record(request).await?;
        let record = self.persist_notification(record, context).await?;
        self.consumer_notification_response(StatusCode::CREATED, record)
            .await
    }

    async fn summary_report(&self) -> Result<http::Response<ApiBody>> {
        let webhook_endpoints = self
            .webhook_endpoints
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let webhook_enabled = webhook_endpoints
            .iter()
            .filter(|record| record.enabled)
            .count();

        let templates = self
            .templates
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let templates_enabled = templates.iter().filter(|record| record.enabled).count();
        let mut templates_by_channel = BTreeMap::new();
        for record in &templates {
            let entry = templates_by_channel
                .entry(record.channel.clone())
                .or_insert(0_usize);
            *entry += 1;
        }

        let preferences = self
            .preferences
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let preferences_enabled = preferences.iter().filter(|record| record.enabled).count();
        let preferences_muted = preferences
            .iter()
            .filter(|record| record.digest_mode == "muted")
            .count();

        let alert_routes = self
            .alert_routes
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let alert_routes_enabled = alert_routes.iter().filter(|record| record.enabled).count();
        let mut alert_routes_by_channel = BTreeMap::new();
        for record in &alert_routes {
            let entry = alert_routes_by_channel
                .entry(record.channel.clone())
                .or_insert(0_usize);
            *entry += 1;
        }

        let notifications = self
            .notifications
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let mut notifications_by_state = BTreeMap::new();
        let mut notifications_by_channel = BTreeMap::new();
        let mut pending = 0_usize;
        let mut sent = 0_usize;
        let mut failed = 0_usize;
        let mut suppressed = 0_usize;
        let mut dead_lettered = 0_usize;
        for record in &notifications {
            let state_key = delivery_state_key(record.state.clone());
            let state_entry = notifications_by_state
                .entry(state_key.to_owned())
                .or_insert(0);
            *state_entry += 1;
            let channel_entry = notifications_by_channel
                .entry(record.channel.clone())
                .or_insert(0_usize);
            *channel_entry += 1;
            match record.state {
                DeliveryState::Queued | DeliveryState::Delivering => {
                    pending = pending.saturating_add(1);
                }
                DeliveryState::Delivered => {
                    sent = sent.saturating_add(1);
                }
                DeliveryState::Failed => {
                    failed = failed.saturating_add(1);
                }
                DeliveryState::Suppressed => {
                    suppressed = suppressed.saturating_add(1);
                }
                DeliveryState::DeadLettered => {
                    dead_lettered = dead_lettered.saturating_add(1);
                }
            }
        }

        let dead_letters = self
            .dead_letters
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .count();

        let summary = NotifySummary {
            webhook_endpoints: NotifyEndpointSummary {
                total: webhook_endpoints.len(),
                enabled: webhook_enabled,
                disabled: webhook_endpoints.len().saturating_sub(webhook_enabled),
            },
            templates: NotifyTemplateSummary {
                total: templates.len(),
                enabled: templates_enabled,
                disabled: templates.len().saturating_sub(templates_enabled),
                by_channel: map_summary_counters(templates_by_channel),
            },
            preferences: NotifyPreferenceSummary {
                total: preferences.len(),
                enabled: preferences_enabled,
                disabled: preferences.len().saturating_sub(preferences_enabled),
                muted: preferences_muted,
            },
            alert_routes: NotifyAlertRouteSummary {
                total: alert_routes.len(),
                enabled: alert_routes_enabled,
                disabled: alert_routes.len().saturating_sub(alert_routes_enabled),
                by_channel: map_summary_counters(alert_routes_by_channel),
            },
            notifications: NotifyNotificationSummary {
                total: notifications.len(),
                pending,
                sent,
                failed,
                suppressed,
                dead_lettered,
                by_state: map_summary_counters(notifications_by_state),
                by_channel: map_summary_counters(notifications_by_channel),
            },
            dead_letters: NotifyDeadLetterSummary {
                total: dead_letters,
            },
        };
        json_response(StatusCode::OK, &summary)
    }

    async fn build_notification_record(
        &self,
        request: CreateNotificationRequest,
    ) -> Result<NotificationRecord> {
        let channel = normalize_channel(&request.channel)?;
        if request.destination.trim().is_empty() {
            return Err(PlatformError::invalid("destination may not be empty"));
        }
        let destination = request.destination.trim().to_owned();
        let template_id = request
            .template_id
            .map(|raw| {
                NotificationTemplateId::parse(raw).map_err(|error| {
                    PlatformError::invalid("invalid template_id").with_detail(error.to_string())
                })
            })
            .transpose()?;
        let template_record = if let Some(template_id) = template_id.as_ref() {
            Some(
                self.templates
                    .get(template_id.as_str())
                    .await?
                    .ok_or_else(|| PlatformError::not_found("template does not exist"))?
                    .value,
            )
        } else {
            None
        };
        if let Some(template) = template_record.as_ref() {
            if !template.enabled {
                return Err(PlatformError::conflict("template is disabled"));
            }
            if template.channel != channel {
                return Err(PlatformError::conflict(
                    "template channel does not match requested channel",
                ));
            }
        }

        let template_vars = request.template_vars.unwrap_or_default();
        let rendered_subject = if let Some(template) = template_record.as_ref() {
            render_template(&template.subject_template, &template_vars)
        } else {
            String::new()
        };
        let rendered_body = if let Some(template) = template_record.as_ref() {
            render_template(&template.body_template, &template_vars)
        } else {
            String::new()
        };
        let subject = if request.subject.trim().is_empty() {
            rendered_subject.trim().to_owned()
        } else {
            request.subject.trim().to_owned()
        };
        let body = if request.body.trim().is_empty() {
            rendered_body.trim().to_owned()
        } else {
            request.body.trim().to_owned()
        };
        if subject.is_empty() || body.is_empty() {
            return Err(PlatformError::invalid(
                "subject and body may not be empty after template rendering",
            ));
        }
        let locale = normalize_locale(
            request
                .locale
                .as_deref()
                .or_else(|| {
                    template_record
                        .as_ref()
                        .map(|template| template.locale.as_str())
                })
                .unwrap_or("en-us"),
        )?;
        let subject_key = request
            .subject_key
            .as_deref()
            .map(normalize_subject_key)
            .transpose()?;
        let case_reference = request
            .case_reference
            .as_deref()
            .map(normalize_case_reference)
            .transpose()?;
        let webhook_endpoint_id = request
            .webhook_endpoint_id
            .map(|raw| {
                WebhookEndpointId::parse(raw).map_err(|error| {
                    PlatformError::invalid("invalid webhook_endpoint_id")
                        .with_detail(error.to_string())
                })
            })
            .transpose()?;
        if channel == "webhook" && webhook_endpoint_id.is_none() {
            return Err(PlatformError::invalid(
                "webhook channel requires webhook_endpoint_id",
            ));
        }
        if channel != "webhook" && webhook_endpoint_id.is_some() {
            return Err(PlatformError::invalid(
                "webhook_endpoint_id is only valid for webhook channel",
            ));
        }
        let endpoint_record = if let Some(endpoint_id) = webhook_endpoint_id.as_ref() {
            Some(
                self.webhook_endpoints
                    .get(endpoint_id.as_str())
                    .await?
                    .ok_or_else(|| PlatformError::not_found("webhook endpoint does not exist"))?
                    .value,
            )
        } else {
            None
        };

        let preference = if let Some(subject_key) = subject_key.as_ref() {
            self.preferences
                .get(&preference_lookup_key(subject_key, &channel))
                .await?
                .map(|stored| stored.value)
        } else {
            None
        };
        let suppressed = preference
            .as_ref()
            .map(|value| !value.enabled || value.digest_mode == "muted")
            .unwrap_or(false);

        let now = OffsetDateTime::now_utc();
        let max_attempts = request
            .max_attempts
            .or_else(|| {
                endpoint_record
                    .as_ref()
                    .map(|endpoint| endpoint.max_attempts)
            })
            .unwrap_or(5)
            .clamp(1, 20);
        let state = if suppressed {
            DeliveryState::Suppressed
        } else {
            DeliveryState::Queued
        };
        let next_attempt_at = if suppressed {
            None
        } else {
            let delay = request.deliver_after_seconds.unwrap_or(0).clamp(0, 86_400);
            Some(now + Duration::seconds(i64::from(delay)))
        };
        let id = NotificationId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate notification id")
                .with_detail(error.to_string())
        })?;
        let signature = self.sign_notification_payload(
            id.as_str(),
            &channel,
            &destination,
            &subject,
            &body,
            &locale,
        )?;
        let record = NotificationRecord {
            id: id.clone(),
            channel: channel.clone(),
            destination,
            subject,
            body,
            template_id,
            subject_key,
            case_reference,
            locale,
            webhook_endpoint_id,
            state,
            attempts: 0,
            max_attempts,
            next_attempt_at,
            last_error: None,
            acknowledged_at: None,
            acknowledged_by: None,
            acknowledgement_note: None,
            snoozed_until: None,
            snoozed_by: None,
            snooze_reason: None,
            escalation_count: 0,
            last_escalated_at: None,
            last_escalated_by: None,
            last_escalated_notification_id: None,
            signature,
            created_at: now,
            updated_at: now,
            history: Vec::new(),
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        Ok(record)
    }

    async fn persist_notification(
        &self,
        mut record: NotificationRecord,
        context: &RequestContext,
    ) -> Result<NotificationRecord> {
        let is_suppressed = record.state == DeliveryState::Suppressed;
        push_history_entry(
            &mut record,
            if is_suppressed {
                NotificationHistoryEventKind::Suppressed
            } else {
                NotificationHistoryEventKind::Queued
            },
            history_actor(context),
            None,
            None,
            None,
        );
        let id = record.id.clone();
        self.notifications
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            if is_suppressed {
                "notify.message.suppressed.v1"
            } else {
                "notify.message.queued.v1"
            },
            "notification",
            id.as_str(),
            if is_suppressed {
                "suppressed"
            } else {
                "queued"
            },
            serde_json::json!({
                "channel": record.channel.as_str(),
                "max_attempts": record.max_attempts,
            }),
            context,
        )
        .await?;
        Ok(record)
    }

    async fn mark_retryable(
        &self,
        notification_id: &str,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let id = NotificationId::parse(notification_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid notification id").with_detail(error.to_string())
        })?;
        let stored = self
            .notifications
            .get(id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("notification does not exist"))?;
        let mut record = stored.value;
        if record.state != DeliveryState::Failed {
            return Err(PlatformError::conflict(
                "notification is not in failed state",
            ));
        }
        record.state = DeliveryState::Queued;
        record.next_attempt_at = Some(OffsetDateTime::now_utc());
        record.last_error = None;
        record.updated_at = OffsetDateTime::now_utc();
        record
            .metadata
            .touch(sha256_hex(record.id.as_str().as_bytes()));
        push_history_entry(
            &mut record,
            NotificationHistoryEventKind::Requeued,
            history_actor(context),
            None,
            None,
            None,
        );
        self.notifications
            .upsert(id.as_str(), record.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "notify.message.requeued.v1",
            "notification",
            id.as_str(),
            "requeued",
            serde_json::json!({}),
            context,
        )
        .await?;
        self.consumer_notification_response(StatusCode::OK, record)
            .await
    }

    async fn replay_dead_letter(
        &self,
        dead_letter_id: &str,
        request: ReplayDeadLetterRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let dead_letter_id = DeadLetterId::parse(dead_letter_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid dead letter id").with_detail(error.to_string())
        })?;
        let reason = request
            .reason
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("operator replay");
        let stored_dead = self
            .dead_letters
            .get(dead_letter_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("dead letter does not exist"))?;
        let mut dead = stored_dead.value;
        let notification_stored = self
            .notifications
            .get(dead.notification_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("notification does not exist"))?;
        let mut notification = notification_stored.value;
        if notification.state != DeliveryState::DeadLettered {
            return Err(PlatformError::conflict(
                "notification is not in dead_lettered state",
            ));
        }
        notification.state = DeliveryState::Queued;
        notification.next_attempt_at = Some(OffsetDateTime::now_utc());
        notification.last_error = Some(String::from("requeued from dead letter"));
        notification.updated_at = OffsetDateTime::now_utc();
        notification
            .metadata
            .touch(sha256_hex(notification.id.as_str().as_bytes()));
        push_history_entry(
            &mut notification,
            NotificationHistoryEventKind::Requeued,
            history_actor(context),
            Some(format!("dead letter replayed: {reason}")),
            None,
            None,
        );
        self.notifications
            .upsert(
                notification.id.as_str(),
                notification.clone(),
                Some(notification_stored.version),
            )
            .await?;

        dead.replay_count = dead.replay_count.saturating_add(1);
        dead.last_replayed_at = Some(OffsetDateTime::now_utc());
        dead.last_replay_reason = Some(reason.to_owned());
        dead.metadata.touch(sha256_hex(dead.id.as_str().as_bytes()));
        self.dead_letters
            .upsert(dead.id.as_str(), dead.clone(), Some(stored_dead.version))
            .await?;

        self.append_event(
            "notify.dead_letter.replayed.v1",
            "notify_dead_letter",
            dead.id.as_str(),
            "replayed",
            serde_json::json!({
                "notification_id": dead.notification_id,
                "reason": reason,
                "replay_count": dead.replay_count,
            }),
            context,
        )
        .await?;
        self.consumer_notification_response(StatusCode::OK, notification)
            .await
    }

    async fn acknowledge_notification(
        &self,
        notification_id: &str,
        request: AcknowledgeNotificationRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let id = NotificationId::parse(notification_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid notification id").with_detail(error.to_string())
        })?;
        let stored = self
            .notifications
            .get(id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("notification does not exist"))?;
        let mut record = stored.value;
        if !matches!(
            record.state,
            DeliveryState::Delivered | DeliveryState::Failed | DeliveryState::DeadLettered
        ) {
            return Err(PlatformError::conflict(
                "notification may only be acknowledged after delivery attempt",
            ));
        }
        if record.acknowledged_at.is_some() {
            return Err(PlatformError::conflict(
                "notification is already acknowledged",
            ));
        }
        let note = normalize_optional_text(request.note.as_deref(), "note", 2048)?;
        let case_reference = request
            .case_reference
            .as_deref()
            .map(normalize_case_reference)
            .transpose()?
            .or_else(|| record.case_reference.clone());
        let acknowledged_at = OffsetDateTime::now_utc();
        let actor = history_actor(context);
        if let Some(case_reference) = case_reference.clone() {
            record.case_reference = Some(case_reference);
        }
        record.acknowledged_at = Some(acknowledged_at);
        record.acknowledged_by = Some(actor.clone());
        record.acknowledgement_note = note.clone();
        record.snoozed_until = None;
        record.snoozed_by = None;
        record.snooze_reason = None;
        record.updated_at = acknowledged_at;
        record
            .metadata
            .touch(sha256_hex(record.id.as_str().as_bytes()));
        push_history_entry(
            &mut record,
            NotificationHistoryEventKind::Acknowledged,
            actor,
            note.clone(),
            case_reference.clone(),
            None,
        );
        self.notifications
            .upsert(id.as_str(), record.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "notify.message.acknowledged.v1",
            "notification",
            id.as_str(),
            "acknowledged",
            serde_json::json!({
                "case_reference": case_reference,
                "note": note,
            }),
            context,
        )
        .await?;
        self.consumer_notification_response(StatusCode::OK, record)
            .await
    }

    async fn snooze_notification(
        &self,
        notification_id: &str,
        request: SnoozeNotificationRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let id = NotificationId::parse(notification_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid notification id").with_detail(error.to_string())
        })?;
        let stored = self
            .notifications
            .get(id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("notification does not exist"))?;
        let mut record = stored.value;
        if matches!(
            record.state,
            DeliveryState::Suppressed | DeliveryState::Delivering
        ) {
            return Err(PlatformError::conflict(
                "notification may not be snoozed in its current state",
            ));
        }
        if record.state == DeliveryState::DeadLettered {
            return Err(PlatformError::conflict(
                "dead-lettered notifications may not be snoozed",
            ));
        }
        if record.acknowledged_at.is_some() {
            return Err(PlatformError::conflict(
                "acknowledged notifications may not be snoozed",
            ));
        }
        let snooze_seconds = request.snooze_seconds.unwrap_or(3600).clamp(60, 604_800);
        let reason = normalize_optional_text(request.reason.as_deref(), "reason", 2048)?;
        let case_reference = request
            .case_reference
            .as_deref()
            .map(normalize_case_reference)
            .transpose()?
            .or_else(|| record.case_reference.clone());
        let snoozed_until =
            OffsetDateTime::now_utc() + Duration::seconds(i64::from(snooze_seconds));
        let actor = history_actor(context);
        if let Some(case_reference) = case_reference.clone() {
            record.case_reference = Some(case_reference);
        }
        record.snoozed_until = Some(snoozed_until);
        record.snoozed_by = Some(actor.clone());
        record.snooze_reason = reason.clone();
        if matches!(record.state, DeliveryState::Queued | DeliveryState::Failed)
            && record
                .next_attempt_at
                .is_none_or(|time| time < snoozed_until)
        {
            record.next_attempt_at = Some(snoozed_until);
        }
        record.updated_at = OffsetDateTime::now_utc();
        record
            .metadata
            .touch(sha256_hex(record.id.as_str().as_bytes()));
        let detail = Some(match reason.as_deref() {
            Some(reason) => format!("snoozed for {snooze_seconds} seconds: {reason}"),
            None => format!("snoozed for {snooze_seconds} seconds"),
        });
        push_history_entry(
            &mut record,
            NotificationHistoryEventKind::Snoozed,
            actor,
            detail.clone(),
            case_reference.clone(),
            None,
        );
        self.notifications
            .upsert(id.as_str(), record.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "notify.message.snoozed.v1",
            "notification",
            id.as_str(),
            "snoozed",
            serde_json::json!({
                "case_reference": case_reference,
                "reason": reason,
                "snoozed_until": snoozed_until,
            }),
            context,
        )
        .await?;
        self.consumer_notification_response(StatusCode::OK, record)
            .await
    }

    async fn escalate_notification(
        &self,
        notification_id: &str,
        request: EscalateNotificationRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let id = NotificationId::parse(notification_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid notification id").with_detail(error.to_string())
        })?;
        let stored = self
            .notifications
            .get(id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("notification does not exist"))?;
        let mut record = stored.value;
        if record.state == DeliveryState::Delivering {
            return Err(PlatformError::conflict(
                "notification may not be escalated while delivery is in progress",
            ));
        }
        if record.acknowledged_at.is_some() {
            return Err(PlatformError::conflict(
                "acknowledged notifications may not be escalated",
            ));
        }
        if record
            .snoozed_until
            .is_some_and(|until| until > OffsetDateTime::now_utc())
        {
            return Err(PlatformError::conflict("notification is currently snoozed"));
        }

        let escalation_channel = normalize_channel(&request.channel)?;
        let reason = normalize_optional_text(request.reason.as_deref(), "reason", 2048)?;
        let case_reference = request
            .case_reference
            .as_deref()
            .map(normalize_case_reference)
            .transpose()?
            .or_else(|| record.case_reference.clone());
        let subject = request
            .subject
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("[ESCALATED] {}", record.subject));
        let body = request
            .body
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| match reason.as_deref() {
                Some(reason) => format!("{}\n\nEscalation reason: {reason}", record.body),
                None => record.body.clone(),
            });
        let webhook_endpoint_id = if escalation_channel == "webhook" {
            request
                .webhook_endpoint_id
                .clone()
                .or_else(|| record.webhook_endpoint_id.as_ref().map(ToString::to_string))
        } else {
            None
        };
        let escalated = self
            .build_notification_record(CreateNotificationRequest {
                channel: escalation_channel.clone(),
                destination: request.destination,
                subject,
                body,
                template_id: None,
                template_vars: None,
                subject_key: request.subject_key.or_else(|| record.subject_key.clone()),
                case_reference: case_reference.clone(),
                locale: request.locale.or_else(|| Some(record.locale.clone())),
                webhook_endpoint_id,
                max_attempts: request.max_attempts,
                deliver_after_seconds: request.deliver_after_seconds,
            })
            .await?;
        let escalated = self.persist_notification(escalated, context).await?;

        let actor = history_actor(context);
        let escalated_id = escalated.id.clone();
        let escalated_destination = escalated.destination.clone();
        let now = OffsetDateTime::now_utc();
        if let Some(case_reference) = case_reference.clone() {
            record.case_reference = Some(case_reference);
        }
        record.escalation_count = record.escalation_count.saturating_add(1);
        record.last_escalated_at = Some(now);
        record.last_escalated_by = Some(actor.clone());
        record.last_escalated_notification_id = Some(escalated_id.clone());
        record.updated_at = now;
        record
            .metadata
            .touch(sha256_hex(record.id.as_str().as_bytes()));
        let detail = Some(match reason.as_deref() {
            Some(reason) => {
                format!("escalated to {escalation_channel}:{escalated_destination}: {reason}")
            }
            None => format!("escalated to {escalation_channel}:{escalated_destination}"),
        });
        push_history_entry(
            &mut record,
            NotificationHistoryEventKind::Escalated,
            actor,
            detail.clone(),
            case_reference.clone(),
            Some(escalated_id.clone()),
        );
        self.notifications
            .upsert(id.as_str(), record, Some(stored.version))
            .await?;
        self.append_event(
            "notify.message.escalated.v1",
            "notification",
            id.as_str(),
            "escalated",
            serde_json::json!({
                "case_reference": case_reference,
                "reason": reason,
                "channel": escalation_channel,
                "destination": escalated_destination,
                "escalated_notification_id": escalated_id,
            }),
            context,
        )
        .await?;
        self.consumer_notification_response(StatusCode::CREATED, escalated)
            .await
    }

    async fn notification_history(&self, notification_id: &str) -> Result<http::Response<ApiBody>> {
        let id = NotificationId::parse(notification_id.to_owned()).map_err(|error| {
            PlatformError::invalid("invalid notification id").with_detail(error.to_string())
        })?;
        let stored = self
            .notifications
            .get(id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("notification does not exist"))?;
        let history = self.consumer_notification_history(stored.value).await;
        json_response(StatusCode::OK, &history)
    }

    async fn dispatch_message(
        &self,
        notification_id: &str,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let notification_id =
            NotificationId::parse(notification_id.to_owned()).map_err(|error| {
                PlatformError::invalid("invalid notification id").with_detail(error.to_string())
            })?;
        let (record, _) = self
            .dispatch_notification(notification_id.as_str(), context)
            .await?;
        self.consumer_notification_response(StatusCode::OK, record)
            .await
    }

    async fn dispatch_sweep(
        &self,
        request: DispatchSweepRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let now = OffsetDateTime::now_utc();
        let limit = request.limit.unwrap_or(100).clamp(1, 1000);
        let mut candidates = self
            .notifications
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| matches!(record.state, DeliveryState::Queued | DeliveryState::Failed))
            .collect::<Vec<_>>();
        candidates.sort_by_key(|record| {
            record
                .next_attempt_at
                .unwrap_or(record.created_at)
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
            suppressed: 0,
            dead_lettered: 0,
            skipped_not_due: 0,
        };
        for id in selected {
            let stored = self.notifications.get(id.as_str()).await?.ok_or_else(|| {
                PlatformError::not_found("notification missing during dispatch sweep")
            })?;
            if let Some(next_attempt_at) = stored.value.next_attempt_at
                && next_attempt_at > now
            {
                summary.skipped_not_due = summary.skipped_not_due.saturating_add(1);
                continue;
            }
            let (_, outcome) = self.dispatch_notification(id.as_str(), context).await?;
            match outcome {
                DispatchOutcome::Delivered => {
                    summary.delivered = summary.delivered.saturating_add(1);
                }
                DispatchOutcome::FailedRetryable => {
                    summary.failed = summary.failed.saturating_add(1);
                }
                DispatchOutcome::Suppressed => {
                    summary.suppressed = summary.suppressed.saturating_add(1);
                }
                DispatchOutcome::DeadLettered => {
                    summary.dead_lettered = summary.dead_lettered.saturating_add(1);
                }
            }
        }
        json_response(StatusCode::OK, &summary)
    }

    async fn dispatch_notification(
        &self,
        notification_id: &str,
        context: &RequestContext,
    ) -> Result<(NotificationRecord, DispatchOutcome)> {
        let stored = self
            .notifications
            .get(notification_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("notification does not exist"))?;
        let mut record = stored.value;
        if record.state == DeliveryState::Suppressed {
            return Ok((record, DispatchOutcome::Suppressed));
        }
        if record.state == DeliveryState::Delivered {
            return Ok((record, DispatchOutcome::Delivered));
        }
        if record.state == DeliveryState::DeadLettered {
            return Ok((record, DispatchOutcome::DeadLettered));
        }
        if let Some(next_attempt_at) = record.next_attempt_at
            && next_attempt_at > OffsetDateTime::now_utc()
        {
            return Err(PlatformError::conflict(
                "notification is still in backoff window",
            ));
        }

        record.state = DeliveryState::Delivering;
        record.attempts = record.attempts.saturating_add(1);
        record.updated_at = OffsetDateTime::now_utc();
        record
            .metadata
            .touch(sha256_hex(record.id.as_str().as_bytes()));

        let delivery = self.simulate_delivery(&record).await;
        match delivery {
            Ok(()) => {
                record.state = DeliveryState::Delivered;
                record.next_attempt_at = None;
                record.last_error = None;
                record.updated_at = OffsetDateTime::now_utc();
                push_history_entry(
                    &mut record,
                    NotificationHistoryEventKind::Delivered,
                    history_actor(context),
                    None,
                    None,
                    None,
                );
                self.notifications
                    .upsert(notification_id, record.clone(), Some(stored.version))
                    .await?;
                self.append_event(
                    "notify.message.delivered.v1",
                    "notification",
                    notification_id,
                    "delivered",
                    serde_json::json!({
                        "attempts": record.attempts,
                        "channel": record.channel,
                    }),
                    context,
                )
                .await?;
                Ok((record, DispatchOutcome::Delivered))
            }
            Err(error) => {
                let reason = error.to_string();
                if record.attempts >= record.max_attempts {
                    record.state = DeliveryState::DeadLettered;
                    record.next_attempt_at = None;
                    record.last_error = Some(reason.clone());
                    record.updated_at = OffsetDateTime::now_utc();
                    let dead_letter_id = DeadLetterId::generate().map_err(|id_error| {
                        PlatformError::unavailable("failed to allocate dead letter id")
                            .with_detail(id_error.to_string())
                    })?;
                    let dead_letter = NotificationDeadLetterRecord {
                        id: dead_letter_id.clone(),
                        notification_id: record.id.clone(),
                        channel: record.channel.clone(),
                        destination: record.destination.clone(),
                        attempts: record.attempts,
                        last_error: reason.clone(),
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
                    push_history_entry(
                        &mut record,
                        NotificationHistoryEventKind::DeadLettered,
                        history_actor(context),
                        Some(reason.clone()),
                        None,
                        None,
                    );
                    self.notifications
                        .upsert(notification_id, record.clone(), Some(stored.version))
                        .await?;
                    self.dead_letters
                        .create(dead_letter_id.as_str(), dead_letter.clone())
                        .await?;
                    self.append_event(
                        "notify.message.dead_lettered.v1",
                        "notification",
                        notification_id,
                        "dead_lettered",
                        serde_json::json!({
                            "attempts": record.attempts,
                            "error": reason,
                            "dead_letter_id": dead_letter.id,
                        }),
                        context,
                    )
                    .await?;
                    Ok((record, DispatchOutcome::DeadLettered))
                } else {
                    let backoff_seconds = self.compute_backoff_seconds(&record).await?;
                    record.state = DeliveryState::Failed;
                    record.next_attempt_at = Some(
                        OffsetDateTime::now_utc() + Duration::seconds(i64::from(backoff_seconds)),
                    );
                    record.last_error = Some(reason.clone());
                    record.updated_at = OffsetDateTime::now_utc();
                    push_history_entry(
                        &mut record,
                        NotificationHistoryEventKind::Failed,
                        history_actor(context),
                        Some(reason.clone()),
                        None,
                        None,
                    );
                    self.notifications
                        .upsert(notification_id, record.clone(), Some(stored.version))
                        .await?;
                    self.append_event(
                        "notify.message.failed.v1",
                        "notification",
                        notification_id,
                        "failed",
                        serde_json::json!({
                            "attempts": record.attempts,
                            "error": reason,
                            "next_attempt_in_seconds": backoff_seconds,
                        }),
                        context,
                    )
                    .await?;
                    Ok((record, DispatchOutcome::FailedRetryable))
                }
            }
        }
    }

    async fn simulate_delivery(&self, record: &NotificationRecord) -> Result<()> {
        if record.destination.trim().is_empty() {
            return Err(PlatformError::invalid("destination may not be empty"));
        }
        match record.channel.as_str() {
            "webhook" => {
                let endpoint_id = record.webhook_endpoint_id.as_ref().ok_or_else(|| {
                    PlatformError::invalid("webhook notification missing endpoint binding")
                })?;
                let endpoint = self
                    .webhook_endpoints
                    .get(endpoint_id.as_str())
                    .await?
                    .ok_or_else(|| PlatformError::not_found("webhook endpoint does not exist"))?;
                if !endpoint.value.enabled {
                    return Err(PlatformError::conflict("webhook endpoint is disabled"));
                }
                if endpoint.value.url.contains("unreachable")
                    || endpoint.value.url.contains("fail")
                    || record.destination.contains("unreachable")
                    || record.destination.contains("fail")
                {
                    return Err(PlatformError::unavailable(
                        "webhook destination unavailable",
                    ));
                }
                Ok(())
            }
            "email" => {
                if !record.destination.contains('@') {
                    return Err(PlatformError::invalid("email destination must contain @"));
                }
                if record.destination.contains("invalid") {
                    return Err(PlatformError::invalid("email destination rejected"));
                }
                Ok(())
            }
            "sms" => {
                if record.destination.contains("invalid") {
                    return Err(PlatformError::invalid("sms destination rejected"));
                }
                if record.body.len() > 1600 {
                    return Err(PlatformError::invalid("sms body exceeds max length"));
                }
                Ok(())
            }
            "in_app" | "operator_alert" | "tenant_alert" | "incident" => {
                if record.destination.contains("invalid") {
                    return Err(PlatformError::invalid("destination rejected"));
                }
                Ok(())
            }
            _ => Err(PlatformError::invalid("unsupported notification channel")),
        }
    }

    async fn compute_backoff_seconds(&self, record: &NotificationRecord) -> Result<u32> {
        let base = if let Some(endpoint_id) = record.webhook_endpoint_id.as_ref() {
            let endpoint = self
                .webhook_endpoints
                .get(endpoint_id.as_str())
                .await?
                .ok_or_else(|| PlatformError::not_found("webhook endpoint does not exist"))?;
            endpoint.value.backoff_base_seconds
        } else {
            30
        };
        let exponent = record.attempts.saturating_sub(1).min(8);
        let multiplier = 1_u32.checked_shl(exponent).unwrap_or(u32::MAX);
        Ok(base.saturating_mul(multiplier).clamp(1, 3600))
    }

    fn sign_notification_payload(
        &self,
        id: &str,
        channel: &str,
        destination: &str,
        subject: &str,
        body: &str,
        locale: &str,
    ) -> Result<String> {
        let canonical = format!("{id}\n{channel}\n{destination}\n{subject}\n{body}\n{locale}");
        let signature = hmac_sha256(&self.signing_key, canonical.as_bytes())?;
        Ok(sha256_hex(&signature))
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
                source_service: String::from("notify"),
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
            .enqueue("notify.events.v1", event, Some(&idempotency))
            .await?;
        Ok(())
    }
}

impl HttpService for NotifyService {
    fn name(&self) -> &'static str {
        "notify"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/notify")];
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
                (Method::GET, ["notify"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                    }),
                )
                .map(Some),
                (Method::GET, ["notify", "webhook-endpoints"]) => {
                    let values = self
                        .webhook_endpoints
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["notify", "summary"]) => self.summary_report().await.map(Some),
                (Method::POST, ["notify", "webhook-endpoints"]) => {
                    let body: CreateWebhookEndpointRequest = parse_json(request).await?;
                    self.create_webhook_endpoint(body, &context).await.map(Some)
                }
                (Method::POST, ["notify", "webhook-endpoints", endpoint_id, "rotate-secret"]) => {
                    let body: RotateWebhookSecretRequest = parse_json(request).await?;
                    self.rotate_webhook_secret(endpoint_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["notify", "templates"]) => {
                    let values = self
                        .templates
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["notify", "templates"]) => {
                    let body: CreateTemplateRequest = parse_json(request).await?;
                    self.create_template(body, &context).await.map(Some)
                }
                (Method::GET, ["notify", "preferences"]) => {
                    let values = self
                        .preferences
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["notify", "preferences"]) => {
                    let body: CreatePreferenceRequest = parse_json(request).await?;
                    self.upsert_preference(body, &context).await.map(Some)
                }
                (Method::GET, ["notify", "alert-routes"]) => {
                    let values = self
                        .alert_routes
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["notify", "alert-routes"]) => {
                    let body: CreateAlertRouteRequest = parse_json(request).await?;
                    self.create_alert_route(body, &context).await.map(Some)
                }
                (Method::POST, ["notify", "alerts", "trigger"]) => {
                    let body: TriggerAlertRequest = parse_json(request).await?;
                    self.trigger_alert(body, &context).await.map(Some)
                }
                (Method::GET, ["notify", "messages"]) => {
                    let values = self
                        .notifications
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, stored)| !stored.deleted)
                        .map(|(_, stored)| stored.value)
                        .collect::<Vec<_>>();
                    let mut consumer_values = Vec::with_capacity(values.len());
                    for value in values {
                        consumer_values.push(self.consumer_notification_record(value).await);
                    }
                    json_response(StatusCode::OK, &consumer_values).map(Some)
                }
                (Method::POST, ["notify", "messages"]) => {
                    let body: CreateNotificationRequest = parse_json(request).await?;
                    self.create_notification(body, &context).await.map(Some)
                }
                (Method::GET, ["notify", "messages", notification_id, "history"]) => {
                    self.notification_history(notification_id).await.map(Some)
                }
                (Method::POST, ["notify", "messages", notification_id, "acknowledge"]) => {
                    let body: AcknowledgeNotificationRequest = parse_json(request).await?;
                    self.acknowledge_notification(notification_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["notify", "messages", notification_id, "snooze"]) => {
                    let body: SnoozeNotificationRequest = parse_json(request).await?;
                    self.snooze_notification(notification_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["notify", "messages", notification_id, "escalate"]) => {
                    let body: EscalateNotificationRequest = parse_json(request).await?;
                    self.escalate_notification(notification_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["notify", "messages", notification_id, "deliver"]) => self
                    .dispatch_message(notification_id, &context)
                    .await
                    .map(Some),
                (Method::POST, ["notify", "messages", notification_id, "retry"]) => self
                    .mark_retryable(notification_id, &context)
                    .await
                    .map(Some),
                (Method::POST, ["notify", "dispatch"]) => {
                    let body: DispatchSweepRequest = parse_json(request).await?;
                    self.dispatch_sweep(body, &context).await.map(Some)
                }
                (Method::GET, ["notify", "dead-letters"]) => {
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
                (Method::POST, ["notify", "dead-letters", dead_letter_id, "replay"]) => {
                    let body: ReplayDeadLetterRequest = parse_json(request).await?;
                    self.replay_dead_letter(dead_letter_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["notify", "outbox"]) => {
                    let values = self.outbox.list_all().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn normalize_channel(value: &str) -> Result<String> {
    let channel = value.trim().to_ascii_lowercase();
    match channel.as_str() {
        "email" | "sms" | "in_app" | "webhook" | "operator_alert" | "tenant_alert" | "incident" => {
            Ok(channel)
        }
        _ => Err(PlatformError::invalid(
            "channel must be one of email/sms/in_app/webhook/operator_alert/tenant_alert/incident",
        )),
    }
}

fn normalize_digest_mode(value: &str) -> Result<String> {
    let mode = value.trim().to_ascii_lowercase();
    match mode.as_str() {
        "immediate" | "hourly" | "daily" | "muted" => Ok(mode),
        _ => Err(PlatformError::invalid(
            "digest_mode must be one of immediate/hourly/daily/muted",
        )),
    }
}

fn normalize_subject_key(value: &str) -> Result<String> {
    let key = value.trim().to_ascii_lowercase();
    if key.is_empty() {
        return Err(PlatformError::invalid("subject_key may not be empty"));
    }
    if key.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || character == ':'
            || character == '_'
            || character == '-'
    }) {
        Ok(key)
    } else {
        Err(PlatformError::invalid(
            "subject_key may only contain [a-z0-9:_-]",
        ))
    }
}

fn normalize_locale(value: &str) -> Result<String> {
    let locale = value.trim().to_ascii_lowercase();
    if locale.is_empty() {
        return Err(PlatformError::invalid("locale may not be empty"));
    }
    if locale
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '-' || character == '_')
    {
        Ok(locale)
    } else {
        Err(PlatformError::invalid("locale may only contain [a-z0-9_-]"))
    }
}

fn normalize_webhook_url(value: &str) -> Result<String> {
    let url = value.trim();
    if url.starts_with("https://") || url.starts_with("http://") {
        Ok(url.to_owned())
    } else {
        Err(PlatformError::invalid(
            "webhook url must start with http:// or https://",
        ))
    }
}

fn normalize_alert_severity(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "info" | "warning" | "error" | "critical" => Ok(normalized),
        // Compatibility aliases retained to avoid breaking existing tenant configs.
        "warn" => Ok(String::from("warning")),
        "high" => Ok(String::from("error")),
        "fatal" => Ok(String::from("critical")),
        _ => Err(PlatformError::invalid(
            "severity must be one of info/warning/error/critical",
        )),
    }
}

fn normalize_case_reference(value: &str) -> Result<String> {
    let reference = value.trim().to_ascii_lowercase();
    if reference.is_empty() {
        return Err(PlatformError::invalid("case_reference may not be empty"));
    }
    if reference.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || character == ':'
            || character == '_'
            || character == '-'
            || character == '/'
    }) {
        Ok(reference)
    } else {
        Err(PlatformError::invalid(
            "case_reference may only contain [a-z0-9:_-/]",
        ))
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity.trim().to_ascii_lowercase().as_str() {
        "info" => 0,
        "warning" | "warn" => 1,
        "error" | "high" => 2,
        "critical" | "fatal" => 3,
        _ => 0,
    }
}

fn preference_lookup_key(subject_key: &str, channel: &str) -> String {
    format!("{subject_key}:{channel}")
}

fn render_template(template: &str, vars: &BTreeMap<String, String>) -> String {
    let mut output = template.to_owned();
    for (key, value) in vars {
        output = output.replace(&format!("{{{{{key}}}}}"), value);
    }
    output
}

fn delivery_state_key(state: DeliveryState) -> &'static str {
    match state {
        DeliveryState::Queued => "queued",
        DeliveryState::Delivering => "delivering",
        DeliveryState::Delivered => "delivered",
        DeliveryState::Failed => "failed",
        DeliveryState::Suppressed => "suppressed",
        DeliveryState::DeadLettered => "dead_lettered",
    }
}

fn map_summary_counters(counters: BTreeMap<String, usize>) -> Vec<NotifySummaryCounter> {
    counters
        .into_iter()
        .map(|(key, count)| NotifySummaryCounter { key, count })
        .collect::<Vec<_>>()
}

fn history_actor(context: &RequestContext) -> String {
    context
        .actor
        .clone()
        .unwrap_or_else(|| String::from("system"))
}

fn normalize_optional_text(
    value: Option<&str>,
    field_name: &str,
    max_len: usize,
) -> Result<Option<String>> {
    let value = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if value.as_ref().is_some_and(|value| value.len() > max_len) {
        return Err(PlatformError::invalid(format!(
            "{field_name} may not exceed {max_len} characters"
        )));
    }
    Ok(value)
}

fn push_history_entry(
    record: &mut NotificationRecord,
    event: NotificationHistoryEventKind,
    actor: String,
    detail: Option<String>,
    case_reference: Option<String>,
    related_notification_id: Option<NotificationId>,
) {
    let case_reference = case_reference.or_else(|| record.case_reference.clone());
    if let Some(case_reference) = case_reference.clone() {
        record.case_reference = Some(case_reference);
    }
    let sequence = record
        .history
        .last()
        .map(|entry| entry.sequence.saturating_add(1))
        .unwrap_or(1);
    record.history.push(NotificationHistoryEntry {
        sequence,
        event,
        occurred_at: OffsetDateTime::now_utc(),
        actor,
        state: record.state.clone(),
        attempts: record.attempts,
        detail,
        case_reference,
        related_notification_id,
    });
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bytes::Bytes;
    use http::Request;
    use http_body_util::BodyExt;
    use http_body_util::Full;
    use serde::{Deserialize, de::DeserializeOwned};
    use tempfile::tempdir;

    use super::{
        AcknowledgeNotificationRequest, CreateAlertRouteRequest, CreateNotificationRequest,
        CreatePreferenceRequest, CreateTemplateRequest, CreateWebhookEndpointRequest,
        DeliveryState, DispatchSweepRequest, EscalateNotificationRequest,
        NotificationDeadLetterRecord, NotificationHistoryEventKind, NotificationHistoryResponse,
        NotificationRecord, NotifyService, ReplayDeadLetterRequest, SnoozeNotificationRequest,
        SupportCaseLinkRecord, TriggerAlertRequest,
    };
    use time::OffsetDateTime;
    use uhost_api::ApiBody;
    use uhost_core::{RequestContext, sha256_hex};
    use uhost_runtime::HttpService;
    use uhost_types::{DeadLetterId, NotificationId, OwnershipScope, ResourceMetadata};

    async fn parse_api_body<T: DeserializeOwned>(response: http::Response<ApiBody>) -> T {
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"))
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
        service: &NotifyService,
        method: &str,
        uri: &str,
        body: Option<&str>,
        context: RequestContext,
    ) -> http::Response<ApiBody> {
        match service
            .handle(service_request(method, uri, body), context)
            .await
        {
            Ok(Some(response)) => response,
            Ok(None) => panic!("route {method} {uri} was not handled"),
            Err(error) => panic!("{error}"),
        }
    }

    #[tokio::test]
    async fn preference_can_suppress_notification() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NotifyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .upsert_preference(
                CreatePreferenceRequest {
                    subject_key: String::from("tenant:alpha"),
                    channel: String::from("email"),
                    enabled: false,
                    digest_mode: Some(String::from("muted")),
                    locale: Some(String::from("en-us")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let response = service
            .create_notification(
                CreateNotificationRequest {
                    channel: String::from("email"),
                    destination: String::from("ops@example.com"),
                    subject: String::from("Planned maintenance"),
                    body: String::from("window"),
                    template_id: None,
                    template_vars: None,
                    subject_key: Some(String::from("tenant:alpha")),
                    case_reference: None,
                    locale: None,
                    webhook_endpoint_id: None,
                    max_attempts: None,
                    deliver_after_seconds: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::CREATED);
        let messages = service
            .notifications
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].1.value.state, super::DeliveryState::Suppressed);
    }

    #[tokio::test]
    async fn webhook_failures_move_to_dead_letters_after_retry_budget() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NotifyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let endpoint = service
            .create_webhook_endpoint(
                CreateWebhookEndpointRequest {
                    name: String::from("failing"),
                    url: String::from("https://unreachable.example/webhook"),
                    signing_secret: String::from("secret"),
                    enabled: Some(true),
                    max_attempts: Some(2),
                    timeout_ms: Some(1000),
                    backoff_base_seconds: Some(1),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(endpoint.status(), http::StatusCode::CREATED);
        let endpoint_id = service
            .webhook_endpoints
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .id
            .to_string();

        let _ = service
            .create_notification(
                CreateNotificationRequest {
                    channel: String::from("webhook"),
                    destination: String::from("https://unreachable.example/webhook"),
                    subject: String::from("hook"),
                    body: String::from("{\"ok\":true}"),
                    template_id: None,
                    template_vars: None,
                    subject_key: None,
                    case_reference: None,
                    locale: Some(String::from("en-us")),
                    webhook_endpoint_id: Some(endpoint_id),
                    max_attempts: Some(2),
                    deliver_after_seconds: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let message_id = service
            .notifications
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .id
            .to_string();

        let _ = service
            .dispatch_message(&message_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .mark_retryable(&message_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .dispatch_message(&message_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let current = service
            .notifications
            .get(&message_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing notification"));
        assert_eq!(current.value.state, super::DeliveryState::DeadLettered);
        let dead_letters = service
            .dead_letters
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(dead_letters.len(), 1);
        assert_eq!(dead_letters[0].1.value.notification_id.as_str(), message_id);
    }

    #[tokio::test]
    async fn template_rendering_and_dead_letter_replay_flow() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NotifyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("incident-default"),
                    channel: String::from("webhook"),
                    locale: String::from("en-us"),
                    subject_template: String::from("Incident {{id}}"),
                    body_template: String::from("Service {{service}} down"),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let template_id = service
            .templates
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .id
            .to_string();

        let _ = service
            .create_webhook_endpoint(
                CreateWebhookEndpointRequest {
                    name: String::from("incident-hook"),
                    url: String::from("https://fail.example/webhook"),
                    signing_secret: String::from("secret"),
                    enabled: Some(true),
                    max_attempts: Some(1),
                    timeout_ms: Some(2000),
                    backoff_base_seconds: Some(1),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let endpoint_id = service
            .webhook_endpoints
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .id
            .to_string();

        let _ = service
            .create_notification(
                CreateNotificationRequest {
                    channel: String::from("webhook"),
                    destination: String::from("https://fail.example/webhook"),
                    subject: String::new(),
                    body: String::new(),
                    template_id: Some(template_id),
                    template_vars: Some(BTreeMap::from([
                        (String::from("id"), String::from("42")),
                        (String::from("service"), String::from("api")),
                    ])),
                    subject_key: None,
                    case_reference: None,
                    locale: None,
                    webhook_endpoint_id: Some(endpoint_id),
                    max_attempts: Some(1),
                    deliver_after_seconds: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created: NotificationRecord = service
            .notifications
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .clone();
        assert_eq!(created.subject, "Incident 42");
        assert_eq!(created.body, "Service api down");

        let _ = service
            .dispatch_sweep(DispatchSweepRequest { limit: Some(10) }, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let dead_letter = service
            .dead_letters
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .clone();
        let replayed = service
            .replay_dead_letter(
                dead_letter.id.as_str(),
                ReplayDeadLetterRequest {
                    reason: Some(String::from("route recovered")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replayed.status(), http::StatusCode::OK);
        let current = service
            .notifications
            .get(created.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing notification"));
        assert_eq!(current.value.state, super::DeliveryState::Queued);
        let updated_dead = service
            .dead_letters
            .get(dead_letter.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing dead letter"));
        assert_eq!(updated_dead.value.replay_count, 1);
    }

    #[tokio::test]
    async fn trigger_alert_routes_to_matching_severity() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NotifyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_alert_route(
                CreateAlertRouteRequest {
                    name: String::from("critical-incidents"),
                    min_severity: String::from("critical"),
                    channel: String::from("incident"),
                    destination: String::from("ops://incident-room"),
                    subject_key: Some(String::from("tenant:alpha")),
                    webhook_endpoint_id: None,
                    cooldown_seconds: Some(60),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_alert_route(
                CreateAlertRouteRequest {
                    name: String::from("warning-and-up"),
                    min_severity: String::from("warning"),
                    channel: String::from("operator_alert"),
                    destination: String::from("ops://primary"),
                    subject_key: Some(String::from("tenant:alpha")),
                    webhook_endpoint_id: None,
                    cooldown_seconds: Some(60),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let result = service
            .trigger_alert(
                TriggerAlertRequest {
                    severity: String::from("error"),
                    title: String::from("latency regression"),
                    body: String::from("p99 latency exceeded threshold"),
                    subject_key: Some(String::from("tenant:alpha")),
                    case_reference: None,
                    dedupe_key: None,
                    labels: BTreeMap::from([(
                        String::from("service"),
                        String::from("api-gateway"),
                    )]),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(result.status(), http::StatusCode::OK);
        let notifications = service
            .notifications
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].1.value.channel, "operator_alert");
    }

    #[tokio::test]
    async fn trigger_alert_returns_persisted_notification_ids() {
        #[derive(Debug, Deserialize)]
        struct TriggerAlertSummaryPayload {
            routed: usize,
            suppressed_by_cooldown: usize,
            route_ids: Vec<String>,
            notification_ids: Vec<String>,
        }

        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NotifyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_alert_route(
                CreateAlertRouteRequest {
                    name: String::from("alerts-a"),
                    min_severity: String::from("warning"),
                    channel: String::from("incident"),
                    destination: String::from("ops://incident-a"),
                    subject_key: Some(String::from("tenant:alpha")),
                    webhook_endpoint_id: None,
                    cooldown_seconds: Some(60),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_alert_route(
                CreateAlertRouteRequest {
                    name: String::from("alerts-b"),
                    min_severity: String::from("warning"),
                    channel: String::from("operator_alert"),
                    destination: String::from("ops://primary"),
                    subject_key: Some(String::from("tenant:alpha")),
                    webhook_endpoint_id: None,
                    cooldown_seconds: Some(60),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .trigger_alert(
                TriggerAlertRequest {
                    severity: String::from("error"),
                    title: String::from("latency regression"),
                    body: String::from("p99 latency exceeded threshold"),
                    subject_key: Some(String::from("tenant:alpha")),
                    case_reference: None,
                    dedupe_key: None,
                    labels: BTreeMap::from([(String::from("service"), String::from("api"))]),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::OK);
        let payload = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let summary: TriggerAlertSummaryPayload =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.routed, 2);
        assert_eq!(summary.suppressed_by_cooldown, 0);
        assert_eq!(summary.route_ids.len(), 2);
        assert_eq!(summary.notification_ids.len(), 2);

        let notifications = service
            .notifications
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(notifications.len(), 2);
        let mut stored_ids = notifications
            .into_iter()
            .map(|(_, stored)| stored.value.id.to_string())
            .collect::<Vec<_>>();
        let mut summary_ids = summary.notification_ids.clone();
        stored_ids.sort();
        summary_ids.sort();
        assert_eq!(stored_ids, summary_ids);
    }

    #[tokio::test]
    async fn trigger_alert_respects_dedupe_cooldown_window() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NotifyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_alert_route(
                CreateAlertRouteRequest {
                    name: String::from("ops-pager"),
                    min_severity: String::from("high"),
                    channel: String::from("incident"),
                    destination: String::from("pager://ops"),
                    subject_key: None,
                    webhook_endpoint_id: None,
                    cooldown_seconds: Some(300),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first = service
            .trigger_alert(
                TriggerAlertRequest {
                    severity: String::from("critical"),
                    title: String::from("db failover"),
                    body: String::from("leader is unavailable"),
                    subject_key: None,
                    case_reference: None,
                    dedupe_key: Some(String::from("db-failover-1")),
                    labels: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first.status(), http::StatusCode::OK);

        let second = service
            .trigger_alert(
                TriggerAlertRequest {
                    severity: String::from("critical"),
                    title: String::from("db failover"),
                    body: String::from("leader is unavailable"),
                    subject_key: None,
                    case_reference: None,
                    dedupe_key: Some(String::from("db-failover-1")),
                    labels: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second.status(), http::StatusCode::OK);

        let notifications = service
            .notifications
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(notifications.len(), 1);
    }

    #[tokio::test]
    async fn summary_report_reflects_persisted_notification_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NotifyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let metadata = |seed: &str| {
            ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(seed.to_owned()),
                sha256_hex(seed.as_bytes()),
            )
        };

        let _ = service
            .create_webhook_endpoint(
                CreateWebhookEndpointRequest {
                    name: String::from("ops-hook"),
                    url: String::from("https://notify.example/hook"),
                    signing_secret: String::from("secret-1"),
                    enabled: Some(true),
                    max_attempts: Some(5),
                    timeout_ms: Some(1000),
                    backoff_base_seconds: Some(1),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_webhook_endpoint(
                CreateWebhookEndpointRequest {
                    name: String::from("disabled-hook"),
                    url: String::from("https://notify.example/disabled"),
                    signing_secret: String::from("secret-2"),
                    enabled: Some(false),
                    max_attempts: Some(5),
                    timeout_ms: Some(1000),
                    backoff_base_seconds: Some(1),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("incident-email"),
                    channel: String::from("email"),
                    locale: String::from("en-us"),
                    subject_template: String::from("Incident {{id}}"),
                    body_template: String::from("Body {{id}}"),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_template(
                CreateTemplateRequest {
                    name: String::from("incident-webhook"),
                    channel: String::from("webhook"),
                    locale: String::from("en-us"),
                    subject_template: String::from("Webhook {{id}}"),
                    body_template: String::from("Payload {{id}}"),
                    enabled: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .upsert_preference(
                CreatePreferenceRequest {
                    subject_key: String::from("tenant:alpha"),
                    channel: String::from("email"),
                    enabled: true,
                    digest_mode: Some(String::from("immediate")),
                    locale: Some(String::from("en-us")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .upsert_preference(
                CreatePreferenceRequest {
                    subject_key: String::from("tenant:beta"),
                    channel: String::from("sms"),
                    enabled: false,
                    digest_mode: Some(String::from("muted")),
                    locale: Some(String::from("en-us")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = service
            .create_alert_route(
                CreateAlertRouteRequest {
                    name: String::from("ops"),
                    min_severity: String::from("warning"),
                    channel: String::from("operator_alert"),
                    destination: String::from("ops://primary"),
                    subject_key: None,
                    webhook_endpoint_id: None,
                    cooldown_seconds: Some(60),
                    enabled: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_alert_route(
                CreateAlertRouteRequest {
                    name: String::from("pager"),
                    min_severity: String::from("critical"),
                    channel: String::from("incident"),
                    destination: String::from("ops://pager"),
                    subject_key: None,
                    webhook_endpoint_id: None,
                    cooldown_seconds: Some(60),
                    enabled: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let now = OffsetDateTime::now_utc();
        let insert_notification = |state: DeliveryState, channel: &str, destination: &str| {
            let id = NotificationId::generate().unwrap_or_else(|error| panic!("{error}"));
            let record = NotificationRecord {
                id: id.clone(),
                channel: String::from(channel),
                destination: String::from(destination),
                subject: String::from("subject"),
                body: String::from("body"),
                template_id: None,
                subject_key: None,
                case_reference: None,
                locale: String::from("en-us"),
                webhook_endpoint_id: None,
                state,
                attempts: 0,
                max_attempts: 3,
                next_attempt_at: Some(now),
                last_error: None,
                acknowledged_at: None,
                acknowledged_by: None,
                acknowledgement_note: None,
                snoozed_until: None,
                snoozed_by: None,
                snooze_reason: None,
                escalation_count: 0,
                last_escalated_at: None,
                last_escalated_by: None,
                last_escalated_notification_id: None,
                signature: String::from("sig"),
                created_at: now,
                updated_at: now,
                history: Vec::new(),
                metadata: metadata(id.as_str()),
            };
            (id, record)
        };

        let (queued_id, queued) =
            insert_notification(DeliveryState::Queued, "email", "a@example.com");
        let (delivering_id, delivering) =
            insert_notification(DeliveryState::Delivering, "sms", "+15550101");
        let (delivered_id, delivered) =
            insert_notification(DeliveryState::Delivered, "operator_alert", "ops://primary");
        let (failed_id, failed) = insert_notification(
            DeliveryState::Failed,
            "webhook",
            "https://notify.example/hook",
        );
        let (suppressed_id, suppressed) =
            insert_notification(DeliveryState::Suppressed, "in_app", "user:1");
        let (dead_id, dead_lettered) =
            insert_notification(DeliveryState::DeadLettered, "incident", "ops://pager");

        let _ = service
            .notifications
            .create(queued_id.as_str(), queued)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .notifications
            .create(delivering_id.as_str(), delivering)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .notifications
            .create(delivered_id.as_str(), delivered)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .notifications
            .create(failed_id.as_str(), failed)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .notifications
            .create(suppressed_id.as_str(), suppressed)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .notifications
            .create(dead_id.as_str(), dead_lettered)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let dead_letter_id = DeadLetterId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .dead_letters
            .create(
                dead_letter_id.as_str(),
                NotificationDeadLetterRecord {
                    id: dead_letter_id.clone(),
                    notification_id: dead_id.clone(),
                    channel: String::from("incident"),
                    destination: String::from("ops://pager"),
                    attempts: 3,
                    last_error: String::from("timeout"),
                    captured_at: now,
                    replay_count: 0,
                    last_replayed_at: None,
                    last_replay_reason: None,
                    metadata: metadata(dead_letter_id.as_str()),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .summary_report()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let summary: serde_json::Value =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(summary["webhook_endpoints"]["total"], 2);
        assert_eq!(summary["webhook_endpoints"]["enabled"], 1);
        assert_eq!(summary["templates"]["total"], 2);
        assert_eq!(summary["templates"]["enabled"], 1);
        assert_eq!(summary["preferences"]["total"], 2);
        assert_eq!(summary["preferences"]["muted"], 1);
        assert_eq!(summary["alert_routes"]["total"], 2);
        assert_eq!(summary["alert_routes"]["enabled"], 1);
        assert_eq!(summary["notifications"]["total"], 6);
        assert_eq!(summary["notifications"]["pending"], 2);
        assert_eq!(summary["notifications"]["sent"], 1);
        assert_eq!(summary["notifications"]["failed"], 1);
        assert_eq!(summary["notifications"]["suppressed"], 1);
        assert_eq!(summary["notifications"]["dead_lettered"], 1);
        assert_eq!(summary["dead_letters"]["total"], 1);

        let by_channel = summary["notifications"]["by_channel"]
            .as_array()
            .unwrap_or_else(|| panic!("notifications.by_channel should be an array"));
        let email_count = by_channel
            .iter()
            .find(|entry| entry["key"] == "email")
            .and_then(|entry| entry["count"].as_u64())
            .unwrap_or_default();
        assert_eq!(email_count, 1);
    }

    #[tokio::test]
    async fn acknowledge_and_history_capture_case_linked_actions() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NotifyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        context.actor = Some(String::from("operator:carver"));

        let created = service
            .create_notification(
                CreateNotificationRequest {
                    channel: String::from("incident"),
                    destination: String::from("ops://incident-room"),
                    subject: String::from("Case review"),
                    body: String::from("review pending"),
                    template_id: None,
                    template_vars: None,
                    subject_key: Some(String::from("tenant:alpha")),
                    case_reference: Some(String::from("support:case-123")),
                    locale: Some(String::from("en-us")),
                    webhook_endpoint_id: None,
                    max_attempts: None,
                    deliver_after_seconds: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), http::StatusCode::CREATED);

        let notification_id = service
            .notifications
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .id
            .to_string();

        let _ = service
            .dispatch_message(&notification_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .snooze_notification(
                &notification_id,
                SnoozeNotificationRequest {
                    snooze_seconds: Some(900),
                    reason: Some(String::from("waiting on operator handoff")),
                    case_reference: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let acknowledged = service
            .acknowledge_notification(
                &notification_id,
                AcknowledgeNotificationRequest {
                    note: Some(String::from("operator accepted case")),
                    case_reference: Some(String::from("support:case-123")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(acknowledged.status(), http::StatusCode::OK);

        let history = service
            .notification_history(&notification_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = history
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let history: NotificationHistoryResponse =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(history.case_reference.as_deref(), Some("support:case-123"));
        assert_eq!(history.acknowledged_by.as_deref(), Some("operator:carver"));
        assert_eq!(history.history.len(), 4);
        assert_eq!(
            history.history[0].event,
            NotificationHistoryEventKind::Queued
        );
        assert_eq!(
            history.history[1].event,
            NotificationHistoryEventKind::Delivered
        );
        assert_eq!(
            history.history[2].event,
            NotificationHistoryEventKind::Snoozed
        );
        assert_eq!(
            history.history[3].event,
            NotificationHistoryEventKind::Acknowledged
        );
        assert!(
            history
                .history
                .iter()
                .all(|entry| { entry.case_reference.as_deref() == Some("support:case-123") }),
            "history entries should retain the case link"
        );
    }

    #[tokio::test]
    async fn notify_consumers_prefer_linked_support_case_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NotifyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("operator:carver");

        let created = service
            .create_notification(
                CreateNotificationRequest {
                    channel: String::from("incident"),
                    destination: String::from("ops://incident-room"),
                    subject: String::from("Support handoff"),
                    body: String::from("follow support workflow"),
                    template_id: None,
                    template_vars: None,
                    subject_key: Some(String::from("tenant:alpha")),
                    case_reference: Some(String::from("support:legacy-case")),
                    locale: Some(String::from("en-us")),
                    webhook_endpoint_id: None,
                    max_attempts: None,
                    deliver_after_seconds: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), http::StatusCode::CREATED);
        let created: NotificationRecord = parse_api_body(created).await;
        assert_eq!(
            created.case_reference.as_deref(),
            Some("support:legacy-case")
        );

        let support_case_id = String::from("aud_supportcase205");
        service
            .support_cases
            .upsert(
                &support_case_id,
                SupportCaseLinkRecord {
                    id: support_case_id.clone(),
                    notify_message_ids: vec![created.id.to_string()],
                    updated_at: OffsetDateTime::now_utc(),
                },
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored = service
            .notifications
            .get(created.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored notification"));
        assert_eq!(
            stored.value.case_reference.as_deref(),
            Some("support:legacy-case")
        );

        let listed_response =
            dispatch_request(&service, "GET", "/notify/messages", None, context.clone()).await;
        assert_eq!(listed_response.status(), http::StatusCode::OK);
        let listed: Vec<NotificationRecord> = parse_api_body(listed_response).await;
        let listed_notification = listed
            .iter()
            .find(|entry| entry.id == created.id)
            .unwrap_or_else(|| panic!("missing listed notification"));
        assert_eq!(
            listed_notification.case_reference.as_deref(),
            Some(support_case_id.as_str())
        );

        let dispatched: NotificationRecord = parse_api_body(
            service
                .dispatch_message(created.id.as_str(), &context)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(
            dispatched.case_reference.as_deref(),
            Some(support_case_id.as_str())
        );

        let history: NotificationHistoryResponse = parse_api_body(
            service
                .notification_history(created.id.as_str())
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(
            history.case_reference.as_deref(),
            Some(support_case_id.as_str())
        );
        assert!(
            history
                .history
                .iter()
                .all(|entry| entry.case_reference.as_deref() == Some(support_case_id.as_str())),
            "history consumers should use the linked support case id"
        );
    }

    #[tokio::test]
    async fn escalation_creates_follow_up_notification_and_links_history() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NotifyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        context.actor = Some(String::from("operator:carver"));

        let _ = service
            .create_notification(
                CreateNotificationRequest {
                    channel: String::from("operator_alert"),
                    destination: String::from("ops://primary"),
                    subject: String::from("approval pending"),
                    body: String::from("change request requires review"),
                    template_id: None,
                    template_vars: None,
                    subject_key: Some(String::from("tenant:alpha")),
                    case_reference: Some(String::from("support:case-42")),
                    locale: Some(String::from("en-us")),
                    webhook_endpoint_id: None,
                    max_attempts: None,
                    deliver_after_seconds: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let original_id = service
            .notifications
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .id
            .to_string();

        let _ = service
            .dispatch_message(&original_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let escalated = service
            .escalate_notification(
                &original_id,
                EscalateNotificationRequest {
                    channel: String::from("incident"),
                    destination: String::from("ops://pager"),
                    subject: None,
                    body: None,
                    subject_key: None,
                    case_reference: None,
                    locale: None,
                    webhook_endpoint_id: None,
                    max_attempts: None,
                    deliver_after_seconds: None,
                    reason: Some(String::from("SLA breach risk")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(escalated.status(), http::StatusCode::CREATED);
        let payload = escalated
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let escalated: NotificationRecord =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(escalated.channel, "incident");
        assert_eq!(escalated.case_reference.as_deref(), Some("support:case-42"));
        assert!(escalated.subject.starts_with("[ESCALATED] "));

        let original = service
            .notifications
            .get(&original_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing notification"));
        assert_eq!(original.value.escalation_count, 1);
        assert_eq!(
            original.value.last_escalated_notification_id.as_ref(),
            Some(&escalated.id)
        );
        assert_eq!(
            original.value.history.last().map(|entry| &entry.event),
            Some(&NotificationHistoryEventKind::Escalated)
        );
        assert_eq!(
            original
                .value
                .history
                .last()
                .and_then(|entry| entry.related_notification_id.as_ref()),
            Some(&escalated.id)
        );
    }

    #[tokio::test]
    async fn http_handle_supports_acknowledge_snooze_escalate_and_history_routes() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = NotifyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("operator:carver");

        let created_response = dispatch_request(
            &service,
            "POST",
            "/notify/messages",
            Some(
                r#"{
                    "channel":"incident",
                    "destination":"ops://incident-room",
                    "subject":"Case review",
                    "body":"review pending",
                    "subject_key":"tenant:alpha",
                    "case_reference":"support:case-123",
                    "locale":"en-us"
                }"#,
            ),
            context.clone(),
        )
        .await;
        assert_eq!(created_response.status(), http::StatusCode::CREATED);
        let created: NotificationRecord = parse_api_body(created_response).await;

        let deliver_uri = format!("/notify/messages/{}/deliver", created.id);
        let delivered_response =
            dispatch_request(&service, "POST", &deliver_uri, None, context.clone()).await;
        assert_eq!(delivered_response.status(), http::StatusCode::OK);
        let delivered: NotificationRecord = parse_api_body(delivered_response).await;
        assert_eq!(delivered.state, DeliveryState::Delivered);

        let snooze_uri = format!("/notify/messages/{}/snooze", created.id);
        let snoozed_response = dispatch_request(
            &service,
            "POST",
            &snooze_uri,
            Some(r#"{"snooze_seconds":900,"reason":"waiting on operator handoff"}"#),
            context.clone(),
        )
        .await;
        assert_eq!(snoozed_response.status(), http::StatusCode::OK);
        let snoozed: NotificationRecord = parse_api_body(snoozed_response).await;
        assert!(snoozed.snoozed_until.is_some());
        assert_eq!(snoozed.case_reference.as_deref(), Some("support:case-123"));

        let acknowledge_uri = format!("/notify/messages/{}/acknowledge", created.id);
        let acknowledged_response = dispatch_request(
            &service,
            "POST",
            &acknowledge_uri,
            Some(r#"{"note":"operator accepted case"}"#),
            context.clone(),
        )
        .await;
        assert_eq!(acknowledged_response.status(), http::StatusCode::OK);
        let acknowledged: NotificationRecord = parse_api_body(acknowledged_response).await;
        assert_eq!(
            acknowledged.acknowledged_by.as_deref(),
            Some("operator:carver")
        );
        assert_eq!(
            acknowledged.acknowledgement_note.as_deref(),
            Some("operator accepted case")
        );
        assert_eq!(
            acknowledged.case_reference.as_deref(),
            Some("support:case-123")
        );

        let history_uri = format!("/notify/messages/{}/history", created.id);
        let history_response =
            dispatch_request(&service, "GET", &history_uri, None, context.clone()).await;
        assert_eq!(history_response.status(), http::StatusCode::OK);
        let history: NotificationHistoryResponse = parse_api_body(history_response).await;
        assert_eq!(history.case_reference.as_deref(), Some("support:case-123"));
        assert_eq!(history.acknowledged_by.as_deref(), Some("operator:carver"));
        assert_eq!(history.history.len(), 4);
        assert_eq!(
            history
                .history
                .iter()
                .map(|entry| entry.event.clone())
                .collect::<Vec<_>>(),
            vec![
                NotificationHistoryEventKind::Queued,
                NotificationHistoryEventKind::Delivered,
                NotificationHistoryEventKind::Snoozed,
                NotificationHistoryEventKind::Acknowledged,
            ]
        );
        assert!(
            history
                .history
                .iter()
                .all(|entry| entry.case_reference.as_deref() == Some("support:case-123")),
            "all history entries should retain the case link"
        );

        let original_response = dispatch_request(
            &service,
            "POST",
            "/notify/messages",
            Some(
                r#"{
                    "channel":"operator_alert",
                    "destination":"ops://primary",
                    "subject":"approval pending",
                    "body":"change request requires review",
                    "subject_key":"tenant:alpha",
                    "case_reference":"support:case-42",
                    "locale":"en-us"
                }"#,
            ),
            context.clone(),
        )
        .await;
        assert_eq!(original_response.status(), http::StatusCode::CREATED);
        let original: NotificationRecord = parse_api_body(original_response).await;

        let original_deliver_uri = format!("/notify/messages/{}/deliver", original.id);
        let original_delivered_response = dispatch_request(
            &service,
            "POST",
            &original_deliver_uri,
            None,
            context.clone(),
        )
        .await;
        assert_eq!(original_delivered_response.status(), http::StatusCode::OK);
        let _: NotificationRecord = parse_api_body(original_delivered_response).await;

        let escalate_uri = format!("/notify/messages/{}/escalate", original.id);
        let escalated_response = dispatch_request(
            &service,
            "POST",
            &escalate_uri,
            Some(
                r#"{
                    "channel":"incident",
                    "destination":"ops://pager",
                    "reason":"SLA breach risk"
                }"#,
            ),
            context.clone(),
        )
        .await;
        assert_eq!(escalated_response.status(), http::StatusCode::CREATED);
        let escalated: NotificationRecord = parse_api_body(escalated_response).await;
        assert_eq!(escalated.channel, "incident");
        assert_eq!(escalated.case_reference.as_deref(), Some("support:case-42"));
        assert!(escalated.subject.starts_with("[ESCALATED] "));

        let original_history_uri = format!("/notify/messages/{}/history", original.id);
        let original_history_response =
            dispatch_request(&service, "GET", &original_history_uri, None, context).await;
        assert_eq!(original_history_response.status(), http::StatusCode::OK);
        let original_history: NotificationHistoryResponse =
            parse_api_body(original_history_response).await;
        assert_eq!(original_history.escalation_count, 1);
        assert_eq!(
            original_history.last_escalated_notification_id.as_ref(),
            Some(&escalated.id)
        );
        assert_eq!(
            original_history.history.last().map(|entry| &entry.event),
            Some(&NotificationHistoryEventKind::Escalated)
        );
        assert_eq!(
            original_history
                .history
                .last()
                .and_then(|entry| entry.related_notification_id.as_ref()),
            Some(&escalated.id)
        );
    }
}
