//! Reusable event relay envelope and durable local backend.
//!
//! Phase 1 keeps event relay persistence file-backed via
//! [`DocumentStore<T>`](crate::document::DocumentStore) while providing a small
//! reusable seam for replayable event delivery. The relay envelope preserves the
//! current outbox-ready state model and adds durable attempt, completion,
//! backoff, and replay metadata that services can adopt incrementally.

use std::path::Path;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use uhost_core::{PlatformError, Result};
use uhost_types::AuditId;

use crate::delivery::{DeliveryState, OutboxMessage};
use crate::document::{
    DocumentChange, DocumentChangePage, DocumentCursor, DocumentStore, StoredDocument,
};

const LOCAL_FILE_RELAY_BACKEND: &str = "local_file";

fn default_relay_backend() -> String {
    String::from(LOCAL_FILE_RELAY_BACKEND)
}

fn normalize_message<T>(mut message: EventRelayEnvelope<T>) -> EventRelayEnvelope<T> {
    message.synchronize_legacy_state();
    message
}

fn normalize_replay_reason(reason: &str) -> String {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return String::from("operator replay");
    }
    trimmed.to_owned()
}

/// Stable cursor used to consume deterministic relay-envelope changes.
pub type RelayCursor = DocumentCursor;

/// One deterministic relay-envelope mutation snapshot.
pub type RelayEnvelopeChange<T> = DocumentChange<EventRelayEnvelope<T>>;

/// One ordered page of deterministic relay-envelope changes.
pub type RelayEnvelopeChangePage<T> = DocumentChangePage<EventRelayEnvelope<T>>;

/// Durable relay metadata tracked alongside one event envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayStatus {
    /// Backend responsible for persisting and relaying the envelope.
    #[serde(default = "default_relay_backend")]
    pub backend: String,
    /// Number of relay attempts recorded for this envelope.
    #[serde(default)]
    pub attempts: u32,
    /// Timestamp of the most recent delivery attempt.
    #[serde(default)]
    pub last_attempt_at: Option<OffsetDateTime>,
    /// Timestamp of the most recent successful delivery.
    #[serde(default)]
    pub delivered_at: Option<OffsetDateTime>,
    /// Most recent delivery error if one exists.
    #[serde(default)]
    pub last_error: Option<String>,
    /// Earliest timestamp when another attempt is eligible.
    #[serde(default)]
    pub next_retry_at: Option<OffsetDateTime>,
    /// Number of replay operations recorded for this envelope.
    #[serde(default)]
    pub replay_count: u32,
    /// Timestamp of the most recent replay request.
    #[serde(default)]
    pub last_replayed_at: Option<OffsetDateTime>,
    /// Operator or controller supplied replay reason.
    #[serde(default)]
    pub last_replay_reason: Option<String>,
}

impl Default for RelayStatus {
    fn default() -> Self {
        Self {
            backend: default_relay_backend(),
            attempts: 0,
            last_attempt_at: None,
            delivered_at: None,
            last_error: None,
            next_retry_at: None,
            replay_count: 0,
            last_replayed_at: None,
            last_replay_reason: None,
        }
    }
}

impl RelayStatus {
    fn record_failure(
        &mut self,
        attempted_at: OffsetDateTime,
        error: String,
        next_retry_at: OffsetDateTime,
    ) -> DeliveryState {
        self.attempts = self.attempts.saturating_add(1);
        self.last_attempt_at = Some(attempted_at);
        self.last_error = Some(error.clone());
        self.next_retry_at = Some(next_retry_at);
        DeliveryState::Failed {
            attempts: self.attempts,
            last_error: error,
            next_retry_at,
        }
    }

    fn record_delivery(&mut self, attempted_at: OffsetDateTime) -> DeliveryState {
        self.attempts = self.attempts.saturating_add(1);
        self.last_attempt_at = Some(attempted_at);
        self.delivered_at = Some(attempted_at);
        self.last_error = None;
        self.next_retry_at = None;
        DeliveryState::Delivered {
            delivered_at: attempted_at,
        }
    }

    fn record_replay(&mut self, replayed_at: OffsetDateTime, reason: String) {
        self.replay_count = self.replay_count.saturating_add(1);
        self.last_replayed_at = Some(replayed_at);
        self.last_replay_reason = Some(reason);
        self.last_error = None;
        self.next_retry_at = None;
    }
}

/// Reusable persisted event envelope used by the phase-1 relay substrate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRelayEnvelope<T> {
    /// Stable envelope identifier.
    pub id: String,
    /// Downstream topic or stream name.
    pub topic: String,
    /// Optional idempotency key used to deduplicate producer retries.
    #[serde(default)]
    pub idempotency_key: Option<String>,
    /// Logical service that emitted the event when known.
    #[serde(default)]
    pub source_service: Option<String>,
    /// Versioned event type when known.
    #[serde(default)]
    pub event_type: Option<String>,
    /// Envelope payload.
    pub payload: T,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Last mutation timestamp.
    pub updated_at: OffsetDateTime,
    /// Current delivery state.
    pub state: DeliveryState,
    /// Durable relay attempt, completion, and replay metadata.
    #[serde(default)]
    pub relay: RelayStatus,
}

impl<T> EventRelayEnvelope<T> {
    /// Convert this relay envelope into the legacy outbox view.
    pub fn into_outbox_message(self) -> OutboxMessage<T> {
        OutboxMessage {
            id: self.id,
            topic: self.topic,
            idempotency_key: self.idempotency_key,
            payload: self.payload,
            created_at: self.created_at,
            updated_at: self.updated_at,
            state: self.state,
        }
    }

    fn synchronize_legacy_state(&mut self) {
        if self.relay.backend.trim().is_empty() {
            self.relay.backend = default_relay_backend();
        }

        match &self.state {
            DeliveryState::Pending => {}
            DeliveryState::Failed {
                attempts,
                last_error,
                next_retry_at,
            } => {
                if self.relay.attempts < *attempts {
                    self.relay.attempts = *attempts;
                }
                if self.relay.last_attempt_at.is_none() {
                    self.relay.last_attempt_at = Some(self.updated_at);
                }
                if self.relay.last_error.is_none() {
                    self.relay.last_error = Some(last_error.clone());
                }
                if self.relay.next_retry_at.is_none() {
                    self.relay.next_retry_at = Some(*next_retry_at);
                }
            }
            DeliveryState::Delivered { delivered_at } => {
                if self.relay.attempts == 0 {
                    self.relay.attempts = 1;
                }
                if self.relay.last_attempt_at.is_none() {
                    self.relay.last_attempt_at = Some(*delivered_at);
                }
                if self.relay.delivered_at.is_none() {
                    self.relay.delivered_at = Some(*delivered_at);
                }
            }
        }
    }

    fn ready_for_delivery(&self, now: OffsetDateTime) -> bool {
        match &self.state {
            DeliveryState::Pending => true,
            DeliveryState::Failed { next_retry_at, .. } => *next_retry_at <= now,
            DeliveryState::Delivered { .. } => false,
        }
    }
}

/// Publish request used to create one relay envelope.
#[derive(Debug, Clone)]
pub struct RelayPublishRequest<T> {
    topic: String,
    payload: T,
    idempotency_key: Option<String>,
    source_service: Option<String>,
    event_type: Option<String>,
}

impl<T> RelayPublishRequest<T> {
    /// Create a new publish request for one topic and payload.
    pub fn new(topic: impl Into<String>, payload: T) -> Self {
        Self {
            topic: topic.into(),
            payload,
            idempotency_key: None,
            source_service: None,
            event_type: None,
        }
    }

    /// Attach an idempotency key used for producer retry deduplication.
    pub fn with_idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    /// Attach the emitting service name.
    pub fn with_source_service(mut self, source_service: impl Into<String>) -> Self {
        self.source_service = Some(source_service.into());
        self
    }

    /// Attach the versioned event type.
    pub fn with_event_type(mut self, event_type: impl Into<String>) -> Self {
        self.event_type = Some(event_type.into());
        self
    }
}

/// File-backed durable event relay.
#[derive(Debug, Clone)]
pub struct DurableEventRelay<T> {
    store: DocumentStore<EventRelayEnvelope<T>>,
}

impl<T> DurableEventRelay<T>
where
    T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
{
    /// Open the file-backed relay backend.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            store: DocumentStore::open(path).await?,
        })
    }

    /// Return the underlying local document store backing this relay.
    pub fn local_document_store(&self) -> DocumentStore<EventRelayEnvelope<T>> {
        self.store.clone()
    }

    /// Build one validated pending relay envelope without persisting it.
    pub fn build_publish_envelope(
        request: RelayPublishRequest<T>,
    ) -> Result<EventRelayEnvelope<T>> {
        let RelayPublishRequest {
            topic,
            payload,
            idempotency_key,
            source_service,
            event_type,
        } = request;

        if topic.trim().is_empty() {
            return Err(PlatformError::invalid("relay topic may not be empty"));
        }
        if source_service
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(PlatformError::invalid(
                "relay source_service may not be empty when provided",
            ));
        }
        if event_type
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(PlatformError::invalid(
                "relay event_type may not be empty when provided",
            ));
        }

        let now = OffsetDateTime::now_utc();
        let id = AuditId::generate()
            .map_err(|error| {
                PlatformError::unavailable("failed to allocate relay envelope id")
                    .with_detail(error.to_string())
            })?
            .to_string();

        Ok(EventRelayEnvelope {
            id,
            topic,
            idempotency_key,
            source_service,
            event_type,
            payload,
            created_at: now,
            updated_at: now,
            state: DeliveryState::Pending,
            relay: RelayStatus::default(),
        })
    }

    /// Publish an event envelope into durable relay storage.
    pub async fn publish(&self, request: RelayPublishRequest<T>) -> Result<EventRelayEnvelope<T>> {
        if let Some(key) = request.idempotency_key.as_deref() {
            let existing = self.list_all().await?.into_iter().find(|message| {
                message.topic == request.topic && message.idempotency_key.as_deref() == Some(key)
            });
            if let Some(message) = existing {
                return Ok(message);
            }
        }

        let message = Self::build_publish_envelope(request)?;
        let id = message.id.clone();
        self.store.create(&id, message.clone()).await?;
        Ok(message)
    }

    /// Fetch one relay envelope by identifier.
    pub async fn get(&self, message_id: &str) -> Result<Option<EventRelayEnvelope<T>>> {
        Ok(self
            .store
            .get(message_id)
            .await?
            .filter(|record| !record.deleted)
            .map(|record| normalize_message(record.value)))
    }

    /// Return the current deterministic change-feed cursor for relay envelopes.
    pub async fn current_cursor(&self) -> Result<RelayCursor> {
        self.store.current_cursor().await
    }

    /// Return one ordered page of relay-envelope changes after the supplied cursor.
    pub async fn changes_since(
        &self,
        cursor: Option<RelayCursor>,
        limit: usize,
    ) -> Result<RelayEnvelopeChangePage<T>> {
        let page = self.store.changes_since(cursor, limit).await?;
        Ok(DocumentChangePage {
            next_cursor: page.next_cursor,
            changes: page
                .changes
                .into_iter()
                .map(|change| DocumentChange {
                    revision: change.revision,
                    key: change.key,
                    document: StoredDocument {
                        version: change.document.version,
                        updated_at: change.document.updated_at,
                        deleted: change.document.deleted,
                        value: normalize_message(change.document.value),
                    },
                })
                .collect(),
        })
    }

    /// List all relay envelopes.
    pub async fn list_all(&self) -> Result<Vec<EventRelayEnvelope<T>>> {
        Ok(self
            .store
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| normalize_message(record.value))
            .collect::<Vec<_>>())
    }

    /// List relay envelopes projected into the legacy outbox view.
    pub async fn list_all_outbox_messages(&self) -> Result<Vec<OutboxMessage<T>>> {
        Ok(self
            .list_all()
            .await?
            .into_iter()
            .map(EventRelayEnvelope::into_outbox_message)
            .collect::<Vec<_>>())
    }

    /// Return envelopes currently eligible for delivery.
    pub async fn list_ready(&self, limit: usize) -> Result<Vec<EventRelayEnvelope<T>>> {
        let now = OffsetDateTime::now_utc();
        let mut ready = self
            .store
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| normalize_message(record.value))
            .filter(|message| message.ready_for_delivery(now))
            .collect::<Vec<_>>();
        ready.sort_by_key(|message| message.created_at);
        if ready.len() > limit {
            ready.truncate(limit);
        }
        Ok(ready)
    }

    /// Mark one relay envelope as successfully delivered.
    pub async fn mark_delivered(&self, message_id: &str) -> Result<EventRelayEnvelope<T>> {
        self.update_message(message_id, |message| {
            let now = OffsetDateTime::now_utc();
            message.updated_at = now;
            message.state = message.relay.record_delivery(now);
        })
        .await
    }

    /// Mark one relay envelope as failed and schedule the next retry window.
    pub async fn mark_failed(
        &self,
        message_id: &str,
        error: impl Into<String>,
        next_retry_at: OffsetDateTime,
    ) -> Result<EventRelayEnvelope<T>> {
        let error = error.into();
        self.update_message(message_id, move |message| {
            let now = OffsetDateTime::now_utc();
            message.updated_at = now;
            message.state = message.relay.record_failure(now, error, next_retry_at);
        })
        .await
    }

    /// Requeue one relay envelope for replay and persist replay metadata.
    pub async fn replay(
        &self,
        message_id: &str,
        reason: impl AsRef<str>,
    ) -> Result<EventRelayEnvelope<T>> {
        let reason = normalize_replay_reason(reason.as_ref());
        self.update_message(message_id, move |message| {
            let now = OffsetDateTime::now_utc();
            message.updated_at = now;
            message.relay.record_replay(now, reason);
            message.state = DeliveryState::Pending;
        })
        .await
    }

    async fn update_message<F>(&self, message_id: &str, mutate: F) -> Result<EventRelayEnvelope<T>>
    where
        F: FnOnce(&mut EventRelayEnvelope<T>),
    {
        let stored = self
            .store
            .get(message_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("relay envelope does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("relay envelope does not exist"));
        }

        let mut message = stored.value;
        message.synchronize_legacy_state();
        mutate(&mut message);
        let stored = self
            .store
            .upsert(message_id, message, Some(stored.version))
            .await?;
        Ok(normalize_message(stored.value))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use tempfile::tempdir;
    use time::Duration;
    use tokio::fs;

    use super::{DurableEventRelay, EventRelayEnvelope, RelayCursor, RelayPublishRequest};
    use crate::delivery::DeliveryState;
    use crate::document::{DocumentCollection, StoredDocument};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct LegacyOutboxMessage<T> {
        id: String,
        topic: String,
        idempotency_key: Option<String>,
        payload: T,
        created_at: time::OffsetDateTime,
        updated_at: time::OffsetDateTime,
        state: DeliveryState,
    }

    #[tokio::test]
    async fn event_relay_persists_replay_and_delivery_metadata() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("relay.json");
        let relay = DurableEventRelay::<Value>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let created = relay
            .publish(
                RelayPublishRequest::new(
                    "identity.events.v1",
                    serde_json::json!({"resource":"user"}),
                )
                .with_idempotency_key("evt-1")
                .with_source_service("identity")
                .with_event_type("identity.user.created.v1"),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let failed = relay
            .mark_failed(
                &created.id,
                "temporary sink outage",
                time::OffsetDateTime::now_utc() - Duration::seconds(1),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(failed.state, DeliveryState::Failed { .. }));
        assert_eq!(failed.relay.attempts, 1);

        let replayed = relay
            .replay(&created.id, "operator replay")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(replayed.state, DeliveryState::Pending));
        assert_eq!(replayed.relay.replay_count, 1);
        assert_eq!(
            replayed.event_type.as_deref(),
            Some("identity.user.created.v1")
        );
        assert_eq!(replayed.source_service.as_deref(), Some("identity"));

        let ready = relay
            .list_ready(10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, created.id);

        let delivered = relay
            .mark_delivered(&created.id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(delivered.state, DeliveryState::Delivered { .. }));
        assert_eq!(delivered.relay.attempts, 2);
        assert_eq!(delivered.relay.replay_count, 1);
        assert!(delivered.relay.delivered_at.is_some());
        assert!(delivered.relay.last_replayed_at.is_some());

        drop(relay);

        let reopened = DurableEventRelay::<Value>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let current = reopened
            .get(&created.id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing relay envelope"));
        assert_eq!(current.relay.backend, "local_file");
        assert_eq!(current.relay.attempts, 2);
        assert_eq!(current.relay.replay_count, 1);
        assert_eq!(
            current.event_type.as_deref(),
            Some("identity.user.created.v1")
        );
        assert_eq!(current.source_service.as_deref(), Some("identity"));
    }

    #[tokio::test]
    async fn event_relay_reads_legacy_outbox_records_without_new_metadata() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("relay.json");
        let now = time::OffsetDateTime::now_utc();
        let next_retry_at = now + Duration::minutes(5);

        let mut records = BTreeMap::new();
        records.insert(
            String::from("msg-1"),
            StoredDocument {
                version: 1,
                updated_at: now,
                deleted: false,
                value: LegacyOutboxMessage {
                    id: String::from("msg-1"),
                    topic: String::from("identity.events.v1"),
                    idempotency_key: Some(String::from("idem-1")),
                    payload: serde_json::json!({"resource":"user"}),
                    created_at: now,
                    updated_at: now,
                    state: DeliveryState::Failed {
                        attempts: 2,
                        last_error: String::from("transport outage"),
                        next_retry_at,
                    },
                },
            },
        );
        let legacy = DocumentCollection {
            schema_version: 1,
            revision: 0,
            compacted_through_revision: 0,
            records,
            changes: Vec::new(),
        };
        let encoded = serde_json::to_vec(&legacy).unwrap_or_else(|error| panic!("{error}"));
        fs::write(&path, encoded)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let relay = DurableEventRelay::<Value>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let values = relay
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(values.len(), 1);
        let envelope: &EventRelayEnvelope<Value> = &values[0];
        assert_eq!(envelope.id, "msg-1");
        assert_eq!(envelope.source_service, None);
        assert_eq!(envelope.event_type, None);
        assert_eq!(envelope.relay.backend, "local_file");
        assert_eq!(envelope.relay.attempts, 2);
        assert_eq!(
            envelope.relay.last_error.as_deref(),
            Some("transport outage")
        );
        assert_eq!(envelope.relay.next_retry_at, Some(next_retry_at));
    }

    #[tokio::test]
    async fn event_relay_projects_legacy_outbox_view_for_compatibility() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let relay = DurableEventRelay::<Value>::open(temp.path().join("relay.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        relay
            .publish(
                RelayPublishRequest::new(
                    "identity.events.v1",
                    serde_json::json!({"resource":"user"}),
                )
                .with_idempotency_key("evt-compat"),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let messages = relay
            .list_all_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].topic, "identity.events.v1");
        assert_eq!(messages[0].idempotency_key.as_deref(), Some("evt-compat"));
        assert!(matches!(messages[0].state, DeliveryState::Pending));
    }

    #[tokio::test]
    async fn event_relay_change_feed_tracks_deterministic_envelope_mutations() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let relay = DurableEventRelay::<Value>::open(temp.path().join("relay.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let origin = relay
            .current_cursor()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(origin, RelayCursor::origin());

        let created = relay
            .publish(
                RelayPublishRequest::new(
                    "identity.events.v1",
                    serde_json::json!({"resource":"user","state":"pending"}),
                )
                .with_idempotency_key("evt-change-feed")
                .with_source_service("identity")
                .with_event_type("identity.user.created.v1"),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        relay
            .mark_failed(
                &created.id,
                "temporary sink outage",
                time::OffsetDateTime::now_utc() - Duration::seconds(1),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        relay
            .replay(&created.id, "controller resume")
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first_page = relay
            .changes_since(Some(origin), 2)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first_page.changes.len(), 2);
        assert_eq!(first_page.changes[0].revision, 1);
        assert_eq!(first_page.changes[0].key, created.id);
        assert_eq!(first_page.changes[0].document.version, 1);
        assert!(!first_page.changes[0].document.deleted);
        assert_eq!(
            first_page.changes[0].document.value.event_type.as_deref(),
            Some("identity.user.created.v1")
        );
        assert!(matches!(
            first_page.changes[0].document.value.state,
            DeliveryState::Pending
        ));
        assert_eq!(first_page.changes[1].revision, 2);
        assert_eq!(first_page.changes[1].key, created.id);
        assert_eq!(first_page.changes[1].document.version, 2);
        assert!(matches!(
            first_page.changes[1].document.value.state,
            DeliveryState::Failed { .. }
        ));
        assert_eq!(first_page.next_cursor.revision, 2);

        let second_page = relay
            .changes_since(Some(first_page.next_cursor), 10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second_page.changes.len(), 1);
        assert_eq!(second_page.changes[0].revision, 3);
        assert_eq!(second_page.changes[0].key, created.id);
        assert_eq!(second_page.changes[0].document.version, 3);
        assert!(matches!(
            second_page.changes[0].document.value.state,
            DeliveryState::Pending
        ));
        assert_eq!(second_page.changes[0].document.value.relay.replay_count, 1);
        assert_eq!(
            second_page.changes[0]
                .document
                .value
                .relay
                .last_replay_reason
                .as_deref(),
            Some("controller resume")
        );
        assert_eq!(second_page.next_cursor.revision, 3);

        let latest = relay
            .current_cursor()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(latest.revision, 3);

        let empty_page = relay
            .changes_since(Some(latest), 10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(empty_page.changes.is_empty());
        assert_eq!(empty_page.next_cursor, latest);
    }

    #[tokio::test]
    async fn event_relay_change_feed_bootstraps_legacy_outbox_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("relay.json");
        let now = time::OffsetDateTime::now_utc();

        let mut records = BTreeMap::new();
        records.insert(
            String::from("msg-legacy"),
            StoredDocument {
                version: 4,
                updated_at: now,
                deleted: false,
                value: LegacyOutboxMessage {
                    id: String::from("msg-legacy"),
                    topic: String::from("identity.events.v1"),
                    idempotency_key: Some(String::from("idem-legacy")),
                    payload: serde_json::json!({"resource":"user"}),
                    created_at: now,
                    updated_at: now,
                    state: DeliveryState::Delivered { delivered_at: now },
                },
            },
        );
        let legacy = DocumentCollection {
            schema_version: 1,
            revision: 0,
            compacted_through_revision: 0,
            records,
            changes: Vec::new(),
        };
        let encoded = serde_json::to_vec(&legacy).unwrap_or_else(|error| panic!("{error}"));
        fs::write(&path, encoded)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let relay = DurableEventRelay::<Value>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let current = relay
            .current_cursor()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(current.revision, 1);

        let page = relay
            .changes_since(None, 10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(page.changes.len(), 1);
        assert_eq!(page.changes[0].revision, 1);
        assert_eq!(page.changes[0].key, "msg-legacy");
        assert_eq!(page.changes[0].document.version, 4);
        assert_eq!(page.changes[0].document.value.relay.backend, "local_file");
        assert_eq!(page.changes[0].document.value.relay.attempts, 1);
        assert_eq!(page.changes[0].document.value.relay.delivered_at, Some(now));
        assert_eq!(page.next_cursor.revision, 1);
    }

    #[tokio::test]
    async fn event_relay_change_feed_rejects_future_cursors() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let relay = DurableEventRelay::<Value>::open(temp.path().join("relay.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        relay
            .publish(RelayPublishRequest::new(
                "identity.events.v1",
                serde_json::json!({"resource":"user"}),
            ))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = relay
            .changes_since(Some(RelayCursor { revision: 2 }), 10)
            .await
            .expect_err("future cursor should conflict");
        assert!(error.to_string().contains("ahead of collection revision 1"));
    }
}
