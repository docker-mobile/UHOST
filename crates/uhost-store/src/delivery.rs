//! Durable outbox and inbox primitives.
//!
//! These adapters implement the minimum durable delivery mechanics needed for
//! event-driven workflows in all-in-one mode:
//! - Outbox for reliable publish/retry
//! - Inbox for idempotent consume/deduplicate
//!
//! The storage model is intentionally simple and portable (JSON documents). In
//! distributed mode, these contracts can be backed by a queue broker while
//! keeping the same service-facing API.

use std::path::Path;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use uhost_core::{PlatformError, Result, sha256_hex};
use uhost_types::AuditId;

use crate::document::DocumentStore;

/// Durable state of an outbox message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "detail")]
pub enum DeliveryState {
    /// Message is ready for dispatch.
    Pending,
    /// A dispatch attempt failed and should be retried later.
    Failed {
        /// Number of failed attempts so far.
        attempts: u32,
        /// Last delivery error.
        last_error: String,
        /// Earliest retry timestamp.
        next_retry_at: OffsetDateTime,
    },
    /// Message was delivered to its downstream transport.
    Delivered {
        /// Delivery timestamp.
        delivered_at: OffsetDateTime,
    },
}

/// Outbox message envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxMessage<T> {
    /// Stable message identifier.
    pub id: String,
    /// Message topic used by downstream subscribers.
    pub topic: String,
    /// Optional idempotency key used to deduplicate producer retries.
    pub idempotency_key: Option<String>,
    /// Message payload.
    pub payload: T,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Last mutation timestamp.
    pub updated_at: OffsetDateTime,
    /// Delivery state.
    pub state: DeliveryState,
}

/// File-backed durable outbox.
#[derive(Debug, Clone)]
pub struct DurableOutbox<T> {
    store: DocumentStore<OutboxMessage<T>>,
}

impl<T> DurableOutbox<T>
where
    T: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static,
{
    /// Open the durable outbox.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            store: DocumentStore::open(path).await?,
        })
    }

    /// Enqueue a message. If `idempotency_key` was already used for the same
    /// topic, the existing message is returned.
    pub async fn enqueue(
        &self,
        topic: &str,
        payload: T,
        idempotency_key: Option<&str>,
    ) -> Result<OutboxMessage<T>> {
        if topic.trim().is_empty() {
            return Err(PlatformError::invalid("outbox topic may not be empty"));
        }

        if let Some(key) = idempotency_key {
            let existing = self
                .store
                .list()
                .await?
                .into_iter()
                .map(|(_, record)| record.value)
                .find(|message| {
                    message.topic == topic && message.idempotency_key.as_deref() == Some(key)
                });
            if let Some(message) = existing {
                return Ok(message);
            }
        }

        let now = OffsetDateTime::now_utc();
        let id = AuditId::generate()
            .map_err(|error| {
                PlatformError::unavailable("failed to allocate outbox id")
                    .with_detail(error.to_string())
            })?
            .to_string();
        let message = OutboxMessage {
            id: id.clone(),
            topic: topic.to_owned(),
            idempotency_key: idempotency_key.map(ToOwned::to_owned),
            payload,
            created_at: now,
            updated_at: now,
            state: DeliveryState::Pending,
        };
        self.store.create(&id, message.clone()).await?;
        Ok(message)
    }

    /// List all outbox messages.
    pub async fn list_all(&self) -> Result<Vec<OutboxMessage<T>>> {
        Ok(self
            .store
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>())
    }

    /// Return messages currently eligible for delivery.
    pub async fn list_ready(&self, limit: usize) -> Result<Vec<OutboxMessage<T>>> {
        let now = OffsetDateTime::now_utc();
        let mut ready = self
            .store
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .filter(|message| match &message.state {
                DeliveryState::Pending => true,
                DeliveryState::Failed { next_retry_at, .. } => *next_retry_at <= now,
                DeliveryState::Delivered { .. } => false,
            })
            .collect::<Vec<_>>();
        ready.sort_by_key(|message| message.created_at);
        if ready.len() > limit {
            ready.truncate(limit);
        }
        Ok(ready)
    }

    /// Mark a message as delivered.
    pub async fn mark_delivered(&self, message_id: &str) -> Result<()> {
        let stored = self
            .store
            .get(message_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("outbox message does not exist"))?;
        let mut message = stored.value;
        message.updated_at = OffsetDateTime::now_utc();
        message.state = DeliveryState::Delivered {
            delivered_at: message.updated_at,
        };
        self.store
            .upsert(message_id, message, Some(stored.version))
            .await?;
        Ok(())
    }

    /// Mark a message as failed with retry schedule.
    pub async fn mark_failed(
        &self,
        message_id: &str,
        error: impl Into<String>,
        next_retry_at: OffsetDateTime,
    ) -> Result<()> {
        let stored = self
            .store
            .get(message_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("outbox message does not exist"))?;
        let mut message = stored.value;
        let attempts = match &message.state {
            DeliveryState::Failed { attempts, .. } => attempts.saturating_add(1),
            _ => 1,
        };
        message.updated_at = OffsetDateTime::now_utc();
        message.state = DeliveryState::Failed {
            attempts,
            last_error: error.into(),
            next_retry_at,
        };
        self.store
            .upsert(message_id, message, Some(stored.version))
            .await?;
        Ok(())
    }
}

/// Inbox record used for idempotent consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxRecord {
    /// Stable record id derived from source topic and message id.
    pub id: String,
    /// Source topic.
    pub topic: String,
    /// Upstream message id.
    pub message_id: String,
    /// Processing status.
    pub status: String,
    /// Last update timestamp.
    pub updated_at: OffsetDateTime,
}

/// File-backed durable inbox.
#[derive(Debug, Clone)]
pub struct DurableInbox {
    store: DocumentStore<InboxRecord>,
}

impl DurableInbox {
    /// Open the durable inbox.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            store: DocumentStore::open(path).await?,
        })
    }

    /// Record message receipt. Returns `true` when this is the first time the
    /// message is seen for the topic.
    pub async fn mark_received(&self, topic: &str, message_id: &str) -> Result<bool> {
        let record_id = dedupe_key(topic, message_id);
        if self.store.get(&record_id).await?.is_some() {
            return Ok(false);
        }

        let record = InboxRecord {
            id: record_id.clone(),
            topic: topic.to_owned(),
            message_id: message_id.to_owned(),
            status: String::from("received"),
            updated_at: OffsetDateTime::now_utc(),
        };
        self.store.create(&record_id, record).await?;
        Ok(true)
    }

    /// Mark an inbox record as processed.
    pub async fn mark_processed(&self, topic: &str, message_id: &str) -> Result<()> {
        let record_id = dedupe_key(topic, message_id);
        let stored = self
            .store
            .get(&record_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("inbox message does not exist"))?;
        let mut record = stored.value;
        record.status = String::from("processed");
        record.updated_at = OffsetDateTime::now_utc();
        self.store
            .upsert(&record_id, record, Some(stored.version))
            .await?;
        Ok(())
    }
}

fn dedupe_key(topic: &str, message_id: &str) -> String {
    sha256_hex(format!("{topic}:{message_id}").as_bytes())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use time::Duration;

    use super::{DeliveryState, DurableInbox, DurableOutbox};

    #[tokio::test]
    async fn outbox_enqueue_is_idempotent_when_key_matches() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let outbox = DurableOutbox::<serde_json::Value>::open(temp.path().join("outbox.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first = outbox
            .enqueue(
                "control.events.v1",
                serde_json::json!({"kind":"deployment"}),
                Some("idem-1"),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second = outbox
            .enqueue(
                "control.events.v1",
                serde_json::json!({"kind":"deployment"}),
                Some("idem-1"),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(first.id, second.id);
        let all = outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn outbox_failed_messages_become_ready_after_backoff() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let outbox = DurableOutbox::<serde_json::Value>::open(temp.path().join("outbox.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let message = outbox
            .enqueue(
                "control.events.v1",
                serde_json::json!({"kind":"workload"}),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        outbox
            .mark_failed(
                &message.id,
                "temporary sink outage",
                time::OffsetDateTime::now_utc() + Duration::minutes(5),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let none_ready = outbox
            .list_ready(10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(none_ready.is_empty());

        outbox
            .mark_failed(
                &message.id,
                "retry now",
                time::OffsetDateTime::now_utc() - Duration::seconds(1),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let ready = outbox
            .list_ready(10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(ready.len(), 1);
        assert!(matches!(ready[0].state, DeliveryState::Failed { .. }));
    }

    #[tokio::test]
    async fn inbox_deduplicates_messages() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let inbox = DurableInbox::open(temp.path().join("inbox.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first = inbox
            .mark_received("control.events.v1", "evt-123")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second = inbox
            .mark_received("control.events.v1", "evt-123")
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(first);
        assert!(!second);
        inbox
            .mark_processed("control.events.v1", "evt-123")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
    }
}
