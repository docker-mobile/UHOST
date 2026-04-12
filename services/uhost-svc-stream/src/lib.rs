//! Managed stream inventory and partitioned-log service.
//!
//! This crate provides the beta stream/log control surface:
//! - durable managed stream records with stream-specific identifiers
//! - durable partition projections
//! - durable replayable log entries
//! - publish and acknowledge mutations
//! - service and per-stream lag summaries
//! - audit and outbox emission for downstream integration

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use http::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uhost_api::{ApiBody, json_response, parse_json, parse_query, path_segments, with_etag};
use uhost_core::{PlatformError, RequestContext, Result, sha256_hex};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{
    AuditLog, DocumentChange, DocumentCollection, DocumentStore, DurableOutbox, StoredDocument,
};
use uhost_types::id::{StreamCheckpointId, StreamConsumerGroupId, StreamConsumerMemberId};
use uhost_types::{
    AuditActor, AuditId, EventHeader, EventPayload, OwnershipScope, PlatformEvent,
    ResourceLifecycleState, ResourceMetadata, ServiceEvent, SubscriptionId,
};

const STREAM_EVENT_TOPIC: &str = "stream.events.v1";
const DEFAULT_RETENTION_HOURS: u32 = 72;
const DEFAULT_MAX_LAG_MESSAGES: u64 = 10_000;
const DEFAULT_DELIVERY_SEMANTICS: &str = "at_least_once";
const DEFAULT_STORAGE_CLASS: &str = "standard";
const DEFAULT_REPLAY_LIMIT: usize = 100;
const MAX_REPLAY_LIMIT: usize = 1_000;

/// Error returned when a managed stream identifier cannot be generated or parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedStreamIdError(String);

impl ManagedStreamIdError {
    fn invalid(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ManagedStreamIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ManagedStreamIdError {}

/// Stream-specific identifier local to the stream service family.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ManagedStreamId(String);

impl ManagedStreamId {
    /// Stable prefix for managed stream identifiers.
    pub const PREFIX: &'static str = "stm";

    /// Generate a new managed stream identifier.
    pub fn generate() -> std::result::Result<Self, ManagedStreamIdError> {
        let generated = AuditId::generate().map_err(|error| {
            ManagedStreamIdError::invalid(format!(
                "failed to allocate managed stream id body: {error}"
            ))
        })?;
        let (_, body) = generated
            .as_str()
            .split_once('_')
            .ok_or_else(|| ManagedStreamIdError::invalid("generated id missing body"))?;
        Ok(Self(format!("{}_{}", Self::PREFIX, body)))
    }

    /// Parse an existing managed stream identifier.
    pub fn parse(value: impl Into<String>) -> std::result::Result<Self, ManagedStreamIdError> {
        Self::try_from(value.into())
    }

    /// Borrow the underlying identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ManagedStreamId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ManagedStreamId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<ManagedStreamId> for String {
    fn from(value: ManagedStreamId) -> Self {
        value.0
    }
}

impl TryFrom<String> for ManagedStreamId {
    type Error = ManagedStreamIdError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        let Some((prefix, body)) = value.split_once('_') else {
            return Err(ManagedStreamIdError::invalid(format!(
                "invalid managed stream id shape `{value}`"
            )));
        };
        if prefix != Self::PREFIX {
            return Err(ManagedStreamIdError::invalid(format!(
                "expected managed stream id prefix `{}`, got `{value}`",
                Self::PREFIX,
            )));
        }
        validate_managed_stream_id_body(body)?;
        Ok(Self(format!("{}_{}", Self::PREFIX, body)))
    }
}

impl TryFrom<&str> for ManagedStreamId {
    type Error = ManagedStreamIdError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

/// Durable managed stream metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamRecord {
    pub id: ManagedStreamId,
    pub name: String,
    pub partition_count: u16,
    pub retention_hours: u32,
    pub storage_class: String,
    pub latest_offset: u64,
    pub published_messages: u64,
    pub published_bytes: u64,
    pub last_publish_at: Option<OffsetDateTime>,
    pub metadata: ResourceMetadata,
}

/// Per-partition projection for one managed stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamPartitionRecord {
    pub stream_id: ManagedStreamId,
    pub partition_index: u16,
    pub latest_partition_offset: u64,
    pub published_messages: u64,
    pub published_bytes: u64,
    pub last_publish_at: Option<OffsetDateTime>,
    pub metadata: ResourceMetadata,
}

/// One replayable partition-log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamLogRecord {
    pub id: AuditId,
    pub stream_id: ManagedStreamId,
    pub partition_index: u16,
    pub stream_offset: u64,
    pub partition_offset: u64,
    pub producer_id: Option<String>,
    pub key: Option<String>,
    pub payload: String,
    pub headers: BTreeMap<String, String>,
    pub byte_count: u64,
    pub published_at: OffsetDateTime,
    pub metadata: ResourceMetadata,
}

/// Durable consumer-group subscription metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionRecord {
    pub id: StreamConsumerGroupId,
    pub member_id: StreamConsumerMemberId,
    pub checkpoint_id: StreamCheckpointId,
    pub stream_id: ManagedStreamId,
    pub consumer_group: String,
    pub delivery_semantics: String,
    pub acknowledged_offset: u64,
    pub lag_messages: u64,
    pub max_lag_messages: u64,
    pub healthy: bool,
    pub last_acknowledged_at: Option<OffsetDateTime>,
    pub metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SubscriptionRecordCompatibility {
    id: String,
    #[serde(default)]
    member_id: Option<String>,
    #[serde(default)]
    checkpoint_id: Option<String>,
    stream_id: ManagedStreamId,
    consumer_group: String,
    delivery_semantics: String,
    acknowledged_offset: u64,
    lag_messages: u64,
    max_lag_messages: u64,
    healthy: bool,
    last_acknowledged_at: Option<OffsetDateTime>,
    metadata: ResourceMetadata,
}

/// Service-level stream, partition, and replay counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamServiceSummary {
    pub stream_count: usize,
    pub partition_count: usize,
    pub subscription_count: usize,
    pub idle_stream_count: usize,
    pub lagging_stream_count: usize,
    pub unhealthy_subscription_count: usize,
    pub total_published_messages: u64,
    pub total_published_bytes: u64,
    pub total_retained_records: usize,
    pub total_retained_record_bytes: u64,
    pub total_lag_messages: u64,
}

/// Per-stream lag projection for operator-visible analytics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamLagSummary {
    pub stream_id: ManagedStreamId,
    pub stream_name: String,
    pub partition_count: u16,
    pub latest_offset: u64,
    pub published_messages: u64,
    pub published_bytes: u64,
    pub last_publish_at: Option<OffsetDateTime>,
    pub subscription_count: usize,
    pub healthy_subscription_count: usize,
    pub total_lag_messages: u64,
    pub max_lag_messages: u64,
}

/// Response returned after appending replayable log records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamPublishResponse {
    pub stream: StreamRecord,
    pub touched_partitions: Vec<StreamPartitionRecord>,
    pub appended_records: Vec<StreamLogRecord>,
}

/// Replay page returned for one stream or one stream partition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamReplayPage {
    pub stream_id: ManagedStreamId,
    pub partition: Option<u16>,
    pub after_offset: u64,
    pub stream_high_watermark: u64,
    pub partition_high_watermark: Option<u64>,
    pub next_offset: Option<u64>,
    pub items: Vec<StreamLogRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateStreamRequest {
    name: String,
    partition_count: Option<u16>,
    retention_hours: Option<u32>,
    storage_class: Option<String>,
    owner_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PublishRecordRequest {
    #[serde(default)]
    partition: Option<u16>,
    #[serde(default)]
    key: Option<String>,
    payload: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PublishStreamRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    records: Vec<PublishRecordRequest>,
    #[serde(default)]
    message_count: Option<u32>,
    #[serde(default)]
    byte_count: Option<u64>,
    producer_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateSubscriptionRequest {
    stream_id: String,
    consumer_group: String,
    delivery_semantics: Option<String>,
    initial_offset: Option<u64>,
    max_lag_messages: Option<u64>,
    owner_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AcknowledgeSubscriptionRequest {
    acknowledged_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedPublishRecord {
    partition_index: u16,
    key: Option<String>,
    payload: String,
    headers: BTreeMap<String, String>,
    byte_count: u64,
}

/// File-backed streaming service.
#[derive(Debug, Clone)]
pub struct StreamService {
    streams: DocumentStore<StreamRecord>,
    partitions: DocumentStore<StreamPartitionRecord>,
    log_entries: DocumentStore<StreamLogRecord>,
    subscriptions: DocumentStore<SubscriptionRecord>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    state_root: PathBuf,
}

impl StreamService {
    /// Open the stream service state directory.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("stream");
        migrate_stream_subscription_store(root.join("subscriptions.json").as_path()).await?;
        let service = Self {
            streams: DocumentStore::open(root.join("streams.json")).await?,
            partitions: DocumentStore::open(root.join("partitions.json")).await?,
            log_entries: DocumentStore::open(root.join("log_entries.json")).await?,
            subscriptions: DocumentStore::open(root.join("subscriptions.json")).await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            state_root: root,
        };
        service.reconcile_all_streams_from_log().await?;
        Ok(service)
    }

    async fn reconcile_all_streams_from_log(&self) -> Result<()> {
        let streams = self
            .streams
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        for stream in streams {
            self.ensure_partition_records_for_stream(&stream).await?;
            self.reconcile_stream_projection_from_log(&stream.id)
                .await?;
        }
        Ok(())
    }

    async fn ensure_partition_records_for_stream(&self, stream: &StreamRecord) -> Result<()> {
        let existing = self
            .list_active_partitions(Some(stream.id.as_str()))
            .await?
            .into_iter()
            .map(|partition| partition.partition_index)
            .collect::<BTreeSet<_>>();

        for partition_index in 0..stream.partition_count {
            if existing.contains(&partition_index) {
                continue;
            }
            let record = build_stream_partition_record(
                &stream.id,
                partition_index,
                stream.metadata.owner_id.clone(),
            );
            let key = partition_key(&stream.id, partition_index);
            self.partitions.create(key.as_str(), record).await?;
        }
        Ok(())
    }

    async fn list_active_streams(&self) -> Result<Vec<StreamRecord>> {
        let mut values = self
            .streams
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.metadata
                .created_at
                .cmp(&right.metadata.created_at)
                .then_with(|| left.id.as_str().cmp(right.id.as_str()))
        });
        Ok(values)
    }

    async fn list_active_partitions(
        &self,
        stream_filter: Option<&str>,
    ) -> Result<Vec<StreamPartitionRecord>> {
        let mut values = self
            .partitions
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| {
                stream_filter.is_none_or(|stream_id| record.stream_id.as_str() == stream_id)
            })
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.stream_id
                .as_str()
                .cmp(right.stream_id.as_str())
                .then_with(|| left.partition_index.cmp(&right.partition_index))
        });
        Ok(values)
    }

    async fn list_active_log_entries(
        &self,
        stream_filter: Option<&str>,
        partition_filter: Option<u16>,
    ) -> Result<Vec<StreamLogRecord>> {
        let mut values = self
            .log_entries
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| {
                stream_filter.is_none_or(|stream_id| record.stream_id.as_str() == stream_id)
            })
            .filter(|record| {
                partition_filter.is_none_or(|partition| record.partition_index == partition)
            })
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.stream_offset
                .cmp(&right.stream_offset)
                .then_with(|| left.partition_index.cmp(&right.partition_index))
                .then_with(|| left.partition_offset.cmp(&right.partition_offset))
        });
        Ok(values)
    }

    async fn list_active_subscriptions(
        &self,
        stream_filter: Option<&str>,
        consumer_group_filter: Option<&str>,
    ) -> Result<Vec<SubscriptionRecord>> {
        let consumer_group_filter =
            consumer_group_filter.map(|value| value.trim().to_ascii_lowercase());
        let mut values = self
            .subscriptions
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|record| {
                stream_filter.is_none_or(|stream_id| record.stream_id.as_str() == stream_id)
            })
            .filter(|record| {
                consumer_group_filter
                    .as_ref()
                    .is_none_or(|group| &record.consumer_group == group)
            })
            .collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.metadata
                .created_at
                .cmp(&right.metadata.created_at)
                .then_with(|| left.id.as_str().cmp(right.id.as_str()))
        });
        Ok(values)
    }

    async fn create_stream(
        &self,
        request: CreateStreamRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let name = normalize_stream_name(&request.name)?;
        let partition_count = request.partition_count.unwrap_or(1);
        validate_partition_count(partition_count)?;
        let retention_hours = request.retention_hours.unwrap_or(DEFAULT_RETENTION_HOURS);
        validate_retention_hours(retention_hours)?;
        let storage_class = normalize_storage_class(request.storage_class.as_deref())?;
        let owner_id = effective_owner_id(request.owner_id, context);

        for stream in self.list_active_streams().await? {
            if stream.name.eq_ignore_ascii_case(&name) {
                return Err(PlatformError::conflict(
                    "stream name must be unique among active streams",
                ));
            }
        }

        let id = ManagedStreamId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate managed stream id")
                .with_detail(error.to_string())
        })?;
        let mut metadata = ResourceMetadata::new(
            OwnershipScope::Tenant,
            owner_id.clone(),
            stream_etag(&id, 0, 0, 0),
        );
        metadata.lifecycle = ResourceLifecycleState::Ready;
        metadata.annotations.insert(
            String::from("stream.lifecycle.storage_class"),
            storage_class.clone(),
        );

        let record = StreamRecord {
            id: id.clone(),
            name,
            partition_count,
            retention_hours,
            storage_class,
            latest_offset: 0,
            published_messages: 0,
            published_bytes: 0,
            last_publish_at: None,
            metadata,
        };
        self.streams.create(id.as_str(), record.clone()).await?;
        self.ensure_partition_records_for_stream(&record).await?;
        self.append_event(
            "stream.stream.created.v1",
            "stream",
            id.as_str(),
            "created",
            serde_json::json!({
                "managed_stream_id": id.as_str(),
                "name": record.name.as_str(),
                "partition_count": record.partition_count,
                "retention_hours": record.retention_hours,
                "storage_class": record.storage_class.as_str(),
            }),
            context,
        )
        .await?;
        with_etag(
            json_response(StatusCode::CREATED, &record)?,
            &record.metadata.etag,
        )
    }

    async fn create_subscription(
        &self,
        request: CreateSubscriptionRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let stream_id = ManagedStreamId::parse(request.stream_id).map_err(|error| {
            PlatformError::invalid("invalid managed stream id").with_detail(error.to_string())
        })?;
        let stream = self.load_active_stream(&stream_id).await?;
        let consumer_group = normalize_consumer_group(&request.consumer_group)?;
        let delivery_semantics =
            normalize_delivery_semantics(request.delivery_semantics.as_deref())?;
        let acknowledged_offset = request.initial_offset.unwrap_or(0);
        if acknowledged_offset > stream.value.latest_offset {
            return Err(PlatformError::invalid(
                "initial_offset may not be ahead of the current stream offset",
            ));
        }
        let max_lag_messages = request.max_lag_messages.unwrap_or(DEFAULT_MAX_LAG_MESSAGES);
        if max_lag_messages == 0 {
            return Err(PlatformError::invalid(
                "max_lag_messages must be greater than zero",
            ));
        }

        for subscription in self
            .list_active_subscriptions(Some(stream_id.as_str()), None)
            .await?
        {
            if subscription.consumer_group == consumer_group {
                return Err(PlatformError::conflict(
                    "consumer group already has an active subscription for this stream",
                ));
            }
        }

        let id = StreamConsumerGroupId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate stream consumer-group id")
                .with_detail(error.to_string())
        })?;
        let member_id = StreamConsumerMemberId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate stream consumer-member id")
                .with_detail(error.to_string())
        })?;
        let checkpoint_id = StreamCheckpointId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate stream checkpoint id")
                .with_detail(error.to_string())
        })?;
        let lag_messages = stream
            .value
            .latest_offset
            .saturating_sub(acknowledged_offset);
        let owner_id = effective_owner_id(request.owner_id, context)
            .or_else(|| stream.value.metadata.owner_id.clone());
        let mut metadata = ResourceMetadata::new(
            OwnershipScope::Tenant,
            owner_id,
            subscription_etag(
                &id,
                &member_id,
                &checkpoint_id,
                &stream_id,
                acknowledged_offset,
                lag_messages,
                max_lag_messages,
            ),
        );
        metadata.lifecycle = ResourceLifecycleState::Ready;
        metadata.annotations.insert(
            String::from("stream.subscription.delivery_semantics"),
            delivery_semantics.clone(),
        );
        let _ = upsert_subscription_metadata_annotations(
            &mut metadata,
            &id,
            &member_id,
            &checkpoint_id,
        );

        let record = SubscriptionRecord {
            id: id.clone(),
            member_id: member_id.clone(),
            checkpoint_id: checkpoint_id.clone(),
            stream_id: stream_id.clone(),
            consumer_group,
            delivery_semantics,
            acknowledged_offset,
            lag_messages,
            max_lag_messages,
            healthy: lag_messages <= max_lag_messages,
            last_acknowledged_at: None,
            metadata,
        };
        self.subscriptions
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "stream.subscription.created.v1",
            "subscription",
            id.as_str(),
            "created",
            serde_json::json!({
                "consumer_group_id": id.as_str(),
                "member_id": member_id.as_str(),
                "checkpoint_id": checkpoint_id.as_str(),
                "stream_id": stream_id.as_str(),
                "consumer_group": record.consumer_group.as_str(),
                "acknowledged_offset": record.acknowledged_offset,
                "lag_messages": record.lag_messages,
            }),
            context,
        )
        .await?;
        with_etag(
            json_response(StatusCode::CREATED, &record)?,
            &record.metadata.etag,
        )
    }

    async fn publish_stream(
        &self,
        stream_id: &str,
        request: PublishStreamRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let stream_id = ManagedStreamId::parse(stream_id).map_err(|error| {
            PlatformError::invalid("invalid managed stream id").with_detail(error.to_string())
        })?;
        let stored_stream = self.load_active_stream(&stream_id).await?;
        self.ensure_partition_records_for_stream(&stored_stream.value)
            .await?;

        let producer_id =
            normalize_optional_token("producer_id", request.producer_id.clone(), 120)?;
        let prepared_records =
            prepare_publish_records(&stored_stream.value, &request, producer_id.as_deref())?;
        let partitions = self
            .list_active_partitions(Some(stream_id.as_str()))
            .await?
            .into_iter()
            .map(|record| (record.partition_index, record.latest_partition_offset))
            .collect::<BTreeMap<_, _>>();

        let mut next_stream_offset = stored_stream.value.latest_offset;
        let mut next_partition_offsets = partitions;
        let mut appended_records = Vec::with_capacity(prepared_records.len());
        let published_at = OffsetDateTime::now_utc();
        for prepared in prepared_records {
            next_stream_offset = next_stream_offset.saturating_add(1);
            let next_partition_offset = next_partition_offsets
                .entry(prepared.partition_index)
                .or_insert(0);
            *next_partition_offset = next_partition_offset.saturating_add(1);

            let entry_id = AuditId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate stream log entry id")
                    .with_detail(error.to_string())
            })?;
            let mut metadata = ResourceMetadata::new(
                OwnershipScope::Tenant,
                stored_stream.value.metadata.owner_id.clone(),
                stream_log_etag(
                    &entry_id,
                    &stream_id,
                    next_stream_offset,
                    prepared.partition_index,
                    *next_partition_offset,
                    prepared.byte_count,
                ),
            );
            metadata.lifecycle = ResourceLifecycleState::Ready;
            metadata.annotations.insert(
                String::from("stream.partition_index"),
                prepared.partition_index.to_string(),
            );
            if let Some(producer_id) = producer_id.as_deref() {
                metadata
                    .annotations
                    .insert(String::from("stream.producer_id"), producer_id.to_owned());
            }

            let record = StreamLogRecord {
                id: entry_id,
                stream_id: stream_id.clone(),
                partition_index: prepared.partition_index,
                stream_offset: next_stream_offset,
                partition_offset: *next_partition_offset,
                producer_id: producer_id.clone(),
                key: prepared.key,
                payload: prepared.payload,
                headers: prepared.headers,
                byte_count: prepared.byte_count,
                published_at,
                metadata,
            };
            let key = stream_log_key(&stream_id, record.partition_index, record.partition_offset);
            if let Err(error) = self.log_entries.create(key.as_str(), record.clone()).await {
                let _ = self.reconcile_stream_projection_from_log(&stream_id).await;
                return Err(error);
            }
            appended_records.push(record);
        }

        self.reconcile_stream_projection_from_log(&stream_id)
            .await?;
        let stream = self.load_active_stream(&stream_id).await?.value;
        let touched_partitions = self
            .list_active_partitions(Some(stream_id.as_str()))
            .await?
            .into_iter()
            .filter(|partition| {
                appended_records
                    .iter()
                    .any(|record| record.partition_index == partition.partition_index)
            })
            .collect::<Vec<_>>();

        self.append_event(
            "stream.stream.published.v1",
            "stream",
            stream.id.as_str(),
            "published",
            serde_json::json!({
                "managed_stream_id": stream.id.as_str(),
                "record_count": appended_records.len(),
                "latest_offset": stream.latest_offset,
                "published_messages": stream.published_messages,
                "published_bytes": stream.published_bytes,
                "touched_partitions": touched_partitions
                    .iter()
                    .map(|partition| partition.partition_index)
                    .collect::<Vec<_>>(),
            }),
            context,
        )
        .await?;

        let response = StreamPublishResponse {
            stream: stream.clone(),
            touched_partitions,
            appended_records,
        };
        with_etag(
            json_response(StatusCode::OK, &response)?,
            &stream.metadata.etag,
        )
    }

    async fn acknowledge_subscription(
        &self,
        subscription_id: &str,
        request: AcknowledgeSubscriptionRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let subscription_id = parse_stream_subscription_lookup_id(subscription_id)?;
        let stored_subscription = self.load_active_subscription(&subscription_id).await?;
        let mut subscription = stored_subscription.value.clone();
        let stream = self.load_active_stream(&subscription.stream_id).await?;

        if request.acknowledged_offset < subscription.acknowledged_offset {
            return Err(PlatformError::conflict(
                "acknowledged_offset may not move backwards",
            ));
        }
        if request.acknowledged_offset > stream.value.latest_offset {
            return Err(PlatformError::invalid(
                "acknowledged_offset may not be ahead of the current stream offset",
            ));
        }

        subscription.acknowledged_offset = request.acknowledged_offset;
        subscription.lag_messages = stream
            .value
            .latest_offset
            .saturating_sub(subscription.acknowledged_offset);
        subscription.healthy = subscription.lag_messages <= subscription.max_lag_messages;
        subscription.last_acknowledged_at = Some(OffsetDateTime::now_utc());
        subscription.metadata.touch(subscription_etag(
            &subscription.id,
            &subscription.member_id,
            &subscription.checkpoint_id,
            &subscription.stream_id,
            subscription.acknowledged_offset,
            subscription.lag_messages,
            subscription.max_lag_messages,
        ));
        self.subscriptions
            .upsert(
                subscription.id.as_str(),
                subscription.clone(),
                Some(stored_subscription.version),
            )
            .await?;

        self.append_event(
            "stream.subscription.acknowledged.v1",
            "subscription",
            subscription.id.as_str(),
            "acknowledged",
            serde_json::json!({
                "consumer_group_id": subscription.id.as_str(),
                "member_id": subscription.member_id.as_str(),
                "checkpoint_id": subscription.checkpoint_id.as_str(),
                "stream_id": subscription.stream_id.as_str(),
                "acknowledged_offset": subscription.acknowledged_offset,
                "lag_messages": subscription.lag_messages,
            }),
            context,
        )
        .await?;
        with_etag(
            json_response(StatusCode::OK, &subscription)?,
            &subscription.metadata.etag,
        )
    }

    async fn get_stream_response(&self, stream_id: &str) -> Result<Response<ApiBody>> {
        let stream_id = ManagedStreamId::parse(stream_id).map_err(|error| {
            PlatformError::invalid("invalid managed stream id").with_detail(error.to_string())
        })?;
        let value = self
            .streams
            .get(stream_id.as_str())
            .await?
            .filter(|stored| !stored.deleted);
        match value {
            Some(stored) => {
                let response = json_response(StatusCode::OK, &Some(stored.value.clone()))?;
                with_etag(response, &stored.value.metadata.etag)
            }
            None => json_response(StatusCode::OK, &Option::<StreamRecord>::None),
        }
    }

    async fn get_subscription_response(&self, subscription_id: &str) -> Result<Response<ApiBody>> {
        let subscription_id = parse_stream_subscription_lookup_id(subscription_id)?;
        let value = self
            .subscriptions
            .get(subscription_id.as_str())
            .await?
            .filter(|stored| !stored.deleted);
        match value {
            Some(stored) => {
                let response = json_response(StatusCode::OK, &Some(stored.value.clone()))?;
                with_etag(response, &stored.value.metadata.etag)
            }
            None => json_response(StatusCode::OK, &Option::<SubscriptionRecord>::None),
        }
    }

    async fn service_summary_response(&self) -> Result<Response<ApiBody>> {
        let summary = self.service_summary().await?;
        json_response(StatusCode::OK, &summary)
    }

    async fn service_summary(&self) -> Result<StreamServiceSummary> {
        let streams = self.list_active_streams().await?;
        let partitions = self.list_active_partitions(None).await?;
        let log_entries = self.list_active_log_entries(None, None).await?;
        let subscriptions = self.list_active_subscriptions(None, None).await?;
        let stream_ids_with_subscriptions = subscriptions
            .iter()
            .map(|subscription| subscription.stream_id.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        let lagging_stream_ids = subscriptions
            .iter()
            .filter(|subscription| subscription.lag_messages > 0)
            .map(|subscription| subscription.stream_id.as_str().to_owned())
            .collect::<BTreeSet<_>>();

        Ok(StreamServiceSummary {
            stream_count: streams.len(),
            partition_count: partitions.len(),
            subscription_count: subscriptions.len(),
            idle_stream_count: streams
                .iter()
                .filter(|stream| !stream_ids_with_subscriptions.contains(stream.id.as_str()))
                .count(),
            lagging_stream_count: lagging_stream_ids.len(),
            unhealthy_subscription_count: subscriptions
                .iter()
                .filter(|subscription| !subscription.healthy)
                .count(),
            total_published_messages: streams.iter().map(|stream| stream.published_messages).sum(),
            total_published_bytes: streams.iter().map(|stream| stream.published_bytes).sum(),
            total_retained_records: log_entries.len(),
            total_retained_record_bytes: log_entries.iter().map(|record| record.byte_count).sum(),
            total_lag_messages: subscriptions
                .iter()
                .map(|subscription| subscription.lag_messages)
                .sum(),
        })
    }

    async fn stream_lag_summary(&self, stream_id: &str) -> Result<Option<StreamLagSummary>> {
        let stream_id = ManagedStreamId::parse(stream_id).map_err(|error| {
            PlatformError::invalid("invalid managed stream id").with_detail(error.to_string())
        })?;
        let stream = self
            .streams
            .get(stream_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .map(|stored| stored.value);
        let Some(stream) = stream else {
            return Ok(None);
        };

        let subscriptions = self
            .list_active_subscriptions(Some(stream.id.as_str()), None)
            .await?;
        Ok(Some(StreamLagSummary {
            stream_id: stream.id.clone(),
            stream_name: stream.name.clone(),
            partition_count: stream.partition_count,
            latest_offset: stream.latest_offset,
            published_messages: stream.published_messages,
            published_bytes: stream.published_bytes,
            last_publish_at: stream.last_publish_at,
            subscription_count: subscriptions.len(),
            healthy_subscription_count: subscriptions
                .iter()
                .filter(|subscription| subscription.healthy)
                .count(),
            total_lag_messages: subscriptions
                .iter()
                .map(|subscription| subscription.lag_messages)
                .sum(),
            max_lag_messages: subscriptions
                .iter()
                .map(|subscription| subscription.lag_messages)
                .max()
                .unwrap_or(0),
        }))
    }

    async fn stream_lag_summary_response(&self, stream_id: &str) -> Result<Response<ApiBody>> {
        let summary = self.stream_lag_summary(stream_id).await?;
        match summary {
            Some(summary) => {
                let response = json_response(StatusCode::OK, &Some(summary.clone()))?;
                with_etag(response, stream_lag_summary_etag(&summary).as_str())
            }
            None => json_response(StatusCode::OK, &Option::<StreamLagSummary>::None),
        }
    }

    async fn stream_partitions_response(&self, stream_id: &str) -> Result<Response<ApiBody>> {
        let stream_id = ManagedStreamId::parse(stream_id).map_err(|error| {
            PlatformError::invalid("invalid managed stream id").with_detail(error.to_string())
        })?;
        self.load_active_stream(&stream_id).await?;
        let values = self
            .list_active_partitions(Some(stream_id.as_str()))
            .await?;
        let response = json_response(StatusCode::OK, &values)?;
        with_etag(
            response,
            stream_partitions_etag(&stream_id, &values).as_str(),
        )
    }

    async fn stream_replay_response(
        &self,
        stream_id: &str,
        query: &BTreeMap<String, String>,
    ) -> Result<Response<ApiBody>> {
        let stream_id = ManagedStreamId::parse(stream_id).map_err(|error| {
            PlatformError::invalid("invalid managed stream id").with_detail(error.to_string())
        })?;
        let stream = self.load_active_stream(&stream_id).await?;
        let partition =
            parse_optional_partition_query(query.get("partition"), stream.value.partition_count)?;
        let after_offset = parse_replay_after_offset(query.get("after_offset"))?;
        let limit = parse_replay_limit(query.get("limit"))?;
        let partition_high_watermark = match partition {
            Some(partition_index) => Some(
                self.list_active_partitions(Some(stream_id.as_str()))
                    .await?
                    .into_iter()
                    .find(|candidate| candidate.partition_index == partition_index)
                    .map(|candidate| candidate.latest_partition_offset)
                    .unwrap_or(0),
            ),
            None => None,
        };

        let mut log_entries = self
            .list_active_log_entries(Some(stream_id.as_str()), partition)
            .await?;
        if let Some(partition_index) = partition {
            log_entries.retain(|record| {
                record.partition_index == partition_index && record.partition_offset > after_offset
            });
            log_entries.sort_by(|left, right| {
                left.partition_offset
                    .cmp(&right.partition_offset)
                    .then_with(|| left.stream_offset.cmp(&right.stream_offset))
            });
        } else {
            log_entries.retain(|record| record.stream_offset > after_offset);
        }

        let has_more = log_entries.len() > limit;
        let items = log_entries.into_iter().take(limit).collect::<Vec<_>>();
        let next_offset = if has_more {
            items.last().map(|record| match partition {
                Some(_) => record.partition_offset,
                None => record.stream_offset,
            })
        } else {
            None
        };
        let page = StreamReplayPage {
            stream_id: stream_id.clone(),
            partition,
            after_offset,
            stream_high_watermark: stream.value.latest_offset,
            partition_high_watermark,
            next_offset,
            items,
        };
        let response = json_response(StatusCode::OK, &page)?;
        with_etag(response, replay_page_etag(&page).as_str())
    }

    async fn load_active_stream(
        &self,
        stream_id: &ManagedStreamId,
    ) -> Result<StoredDocument<StreamRecord>> {
        let stored = self
            .streams
            .get(stream_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("stream does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("stream does not exist"));
        }
        Ok(stored)
    }

    async fn load_active_subscription(
        &self,
        subscription_id: &StreamConsumerGroupId,
    ) -> Result<StoredDocument<SubscriptionRecord>> {
        let stored = self
            .subscriptions
            .get(subscription_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("subscription does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("subscription does not exist"));
        }
        Ok(stored)
    }

    async fn reconcile_stream_projection_from_log(
        &self,
        stream_id: &ManagedStreamId,
    ) -> Result<()> {
        let stored_stream = self.load_active_stream(stream_id).await?;
        let mut stream = stored_stream.value.clone();
        let log_entries = self
            .list_active_log_entries(Some(stream_id.as_str()), None)
            .await?;

        // The retained log is the source of truth for stream and partition counters.
        // When it is empty, all derived offsets and lag projections must collapse back to zero.
        let mut per_partition = BTreeMap::<u16, (u64, u64, u64, Option<OffsetDateTime>)>::new();
        let latest_offset = log_entries
            .iter()
            .map(|record| record.stream_offset)
            .max()
            .unwrap_or(0);
        let published_messages = u64::try_from(log_entries.len()).map_err(|error| {
            PlatformError::unavailable("stream log entry count exceeded u64")
                .with_detail(error.to_string())
        })?;
        let published_bytes = log_entries
            .iter()
            .map(|record| record.byte_count)
            .sum::<u64>();
        let last_publish_at = log_entries.iter().map(|record| record.published_at).max();

        for record in &log_entries {
            let slot = per_partition
                .entry(record.partition_index)
                .or_insert((0, 0, 0, None));
            slot.0 = slot.0.max(record.partition_offset);
            slot.1 = slot.1.saturating_add(1);
            slot.2 = slot.2.saturating_add(record.byte_count);
            slot.3 = match slot.3 {
                Some(existing) => Some(existing.max(record.published_at)),
                None => Some(record.published_at),
            };
        }

        if stream.latest_offset != latest_offset
            || stream.published_messages != published_messages
            || stream.published_bytes != published_bytes
            || stream.last_publish_at != last_publish_at
        {
            stream.latest_offset = latest_offset;
            stream.published_messages = published_messages;
            stream.published_bytes = published_bytes;
            stream.last_publish_at = last_publish_at;
            stream.metadata.touch(stream_etag(
                &stream.id,
                stream.latest_offset,
                stream.published_messages,
                stream.published_bytes,
            ));
            self.streams
                .upsert(
                    stream.id.as_str(),
                    stream.clone(),
                    Some(stored_stream.version),
                )
                .await?;
        }

        let existing_partitions = self
            .list_active_partitions(Some(stream_id.as_str()))
            .await?
            .into_iter()
            .map(|record| (record.partition_index, record))
            .collect::<BTreeMap<_, _>>();
        for partition_index in 0..stream.partition_count {
            let stats = per_partition
                .get(&partition_index)
                .copied()
                .unwrap_or((0, 0, 0, None));
            let record = existing_partitions
                .get(&partition_index)
                .cloned()
                .unwrap_or_else(|| {
                    build_stream_partition_record(
                        &stream.id,
                        partition_index,
                        stream.metadata.owner_id.clone(),
                    )
                });
            if record.latest_partition_offset == stats.0
                && record.published_messages == stats.1
                && record.published_bytes == stats.2
                && record.last_publish_at == stats.3
            {
                continue;
            }

            let key = partition_key(&stream.id, partition_index);
            let stored_partition = self.partitions.get(key.as_str()).await?;
            let mut updated = record;
            updated.latest_partition_offset = stats.0;
            updated.published_messages = stats.1;
            updated.published_bytes = stats.2;
            updated.last_publish_at = stats.3;
            updated.metadata.touch(stream_partition_etag(
                &updated.stream_id,
                updated.partition_index,
                updated.latest_partition_offset,
                updated.published_messages,
                updated.published_bytes,
            ));
            match stored_partition {
                Some(stored) if !stored.deleted => {
                    let key = partition_key(&stream.id, partition_index);
                    self.partitions
                        .upsert(key.as_str(), updated, Some(stored.version))
                        .await?;
                }
                _ => {
                    let key = partition_key(&stream.id, partition_index);
                    self.partitions.upsert(key.as_str(), updated, None).await?;
                }
            }
        }

        self.recalculate_subscriptions_for_stream(&stream).await
    }

    async fn recalculate_subscriptions_for_stream(&self, stream: &StreamRecord) -> Result<()> {
        let subscriptions = self.subscriptions.list().await?;
        for (key, stored) in subscriptions {
            if stored.deleted || stored.value.stream_id != stream.id {
                continue;
            }
            let mut subscription = stored.value;
            subscription.lag_messages = stream
                .latest_offset
                .saturating_sub(subscription.acknowledged_offset);
            subscription.healthy = subscription.lag_messages <= subscription.max_lag_messages;
            subscription.metadata.touch(subscription_etag(
                &subscription.id,
                &subscription.member_id,
                &subscription.checkpoint_id,
                &subscription.stream_id,
                subscription.acknowledged_offset,
                subscription.lag_messages,
                subscription.max_lag_messages,
            ));
            self.subscriptions
                .upsert(&key, subscription, Some(stored.version))
                .await?;
        }
        Ok(())
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
                    PlatformError::unavailable("failed to allocate stream event id")
                        .with_detail(error.to_string())
                })?,
                event_type: event_type.to_owned(),
                schema_version: 1,
                source_service: String::from("stream"),
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
            .enqueue(STREAM_EVENT_TOPIC, event, Some(&idempotency))
            .await?;
        Ok(())
    }
}

impl HttpService for StreamService {
    fn name(&self) -> &'static str {
        "stream"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/stream")];
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
                (Method::GET, ["stream"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root.display().to_string(),
                    }),
                )
                .map(Some),
                (Method::GET, ["stream", "summary"]) => {
                    self.service_summary_response().await.map(Some)
                }
                (Method::GET, ["stream", "streams"]) => {
                    let values = self.list_active_streams().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["stream", "streams"]) => {
                    let body: CreateStreamRequest = parse_json(request).await?;
                    self.create_stream(body, &context).await.map(Some)
                }
                (Method::GET, ["stream", "streams", stream_id]) => {
                    self.get_stream_response(stream_id).await.map(Some)
                }
                (Method::GET, ["stream", "streams", stream_id, "partitions"]) => {
                    self.stream_partitions_response(stream_id).await.map(Some)
                }
                (Method::POST, ["stream", "streams", stream_id, "publish"]) => {
                    let body: PublishStreamRequest = parse_json(request).await?;
                    self.publish_stream(stream_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["stream", "streams", stream_id, "replay"]) => self
                    .stream_replay_response(stream_id, &query)
                    .await
                    .map(Some),
                (Method::GET, ["stream", "streams", stream_id, "lag-summary"]) => {
                    self.stream_lag_summary_response(stream_id).await.map(Some)
                }
                (Method::GET, ["stream", "subscriptions"]) => {
                    let stream_filter = query.get("stream_id").map(String::as_str);
                    let consumer_group_filter = query.get("consumer_group").map(String::as_str);
                    let values = self
                        .list_active_subscriptions(stream_filter, consumer_group_filter)
                        .await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["stream", "subscriptions"]) => {
                    let body: CreateSubscriptionRequest = parse_json(request).await?;
                    self.create_subscription(body, &context).await.map(Some)
                }
                (Method::GET, ["stream", "subscriptions", subscription_id]) => self
                    .get_subscription_response(subscription_id)
                    .await
                    .map(Some),
                (Method::POST, ["stream", "subscriptions", subscription_id, "ack"]) => {
                    let body: AcknowledgeSubscriptionRequest = parse_json(request).await?;
                    self.acknowledge_subscription(subscription_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["stream", "outbox"]) => {
                    let values = self.outbox.list_all().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

async fn migrate_stream_subscription_store(path: &Path) -> Result<()> {
    let payload = match fs::read(path).await {
        Ok(payload) => payload,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(
                PlatformError::unavailable("failed to read stream subscription store")
                    .with_detail(error.to_string()),
            );
        }
    };
    let collection: DocumentCollection<SubscriptionRecordCompatibility> =
        serde_json::from_slice(&payload).map_err(|error| {
            PlatformError::unavailable("failed to decode stream subscription store")
                .with_detail(error.to_string())
        })?;
    let (migrated, changed) = migrate_subscription_collection(collection)?;
    if !changed {
        return Ok(());
    }
    let payload = serde_json::to_vec(&migrated).map_err(|error| {
        PlatformError::unavailable("failed to encode migrated stream subscription store")
            .with_detail(error.to_string())
    })?;
    write_stream_state_atomically(path, &payload).await
}

fn migrate_subscription_collection(
    collection: DocumentCollection<SubscriptionRecordCompatibility>,
) -> Result<(DocumentCollection<SubscriptionRecord>, bool)> {
    let mut changed = false;
    let mut records = BTreeMap::new();
    for (key, stored) in collection.records {
        let StoredDocument {
            version,
            updated_at,
            deleted,
            value,
        } = stored;
        let (value, value_changed) = migrate_subscription_record(value)?;
        let normalized_key = value.id.as_str().to_owned();
        if normalized_key != key {
            changed = true;
        }
        changed |= value_changed;
        if records
            .insert(
                normalized_key.clone(),
                StoredDocument {
                    version,
                    updated_at,
                    deleted,
                    value,
                },
            )
            .is_some()
        {
            return Err(PlatformError::conflict(format!(
                "stream subscription migration produced duplicate key `{normalized_key}`",
            )));
        }
    }

    let mut changes = Vec::with_capacity(collection.changes.len());
    for change in collection.changes {
        let DocumentChange {
            revision,
            key,
            document,
        } = change;
        let StoredDocument {
            version,
            updated_at,
            deleted,
            value,
        } = document;
        let (value, value_changed) = migrate_subscription_record(value)?;
        let normalized_key = value.id.as_str().to_owned();
        if normalized_key != key {
            changed = true;
        }
        changed |= value_changed;
        changes.push(DocumentChange {
            revision,
            key: normalized_key,
            document: StoredDocument {
                version,
                updated_at,
                deleted,
                value,
            },
        });
    }

    Ok((
        DocumentCollection {
            schema_version: collection.schema_version,
            revision: collection.revision,
            compacted_through_revision: collection.compacted_through_revision,
            records,
            changes,
        },
        changed,
    ))
}

fn migrate_subscription_record(
    record: SubscriptionRecordCompatibility,
) -> Result<(SubscriptionRecord, bool)> {
    let mut changed = false;
    let (id, id_changed) =
        parse_or_migrate_stream_consumer_group_id(record.id.as_str()).map_err(|error| {
            PlatformError::invalid("invalid persisted stream subscription record")
                .with_detail(error)
        })?;
    changed |= id_changed;

    let (member_id, member_changed) = match record.member_id.as_deref() {
        Some(value) => parse_or_migrate_stream_consumer_member_id(value).map_err(|error| {
            PlatformError::invalid("invalid persisted stream subscription record")
                .with_detail(error)
        })?,
        None => (
            derive_stream_consumer_member_id(&id).map_err(|error| {
                PlatformError::invalid("invalid persisted stream subscription record")
                    .with_detail(error)
            })?,
            true,
        ),
    };
    changed |= member_changed;

    let (checkpoint_id, checkpoint_changed) = match record.checkpoint_id.as_deref() {
        Some(value) => parse_or_migrate_stream_checkpoint_id(value).map_err(|error| {
            PlatformError::invalid("invalid persisted stream subscription record")
                .with_detail(error)
        })?,
        None => (
            derive_stream_checkpoint_id(&id).map_err(|error| {
                PlatformError::invalid("invalid persisted stream subscription record")
                    .with_detail(error)
            })?,
            true,
        ),
    };
    changed |= checkpoint_changed;

    let mut metadata = record.metadata;
    changed |= normalize_subscription_metadata_for_migration(
        &mut metadata,
        &id,
        &member_id,
        &checkpoint_id,
        &record.stream_id,
        record.acknowledged_offset,
        record.lag_messages,
        record.max_lag_messages,
    );

    Ok((
        SubscriptionRecord {
            id,
            member_id,
            checkpoint_id,
            stream_id: record.stream_id,
            consumer_group: record.consumer_group,
            delivery_semantics: record.delivery_semantics,
            acknowledged_offset: record.acknowledged_offset,
            lag_messages: record.lag_messages,
            max_lag_messages: record.max_lag_messages,
            healthy: record.healthy,
            last_acknowledged_at: record.last_acknowledged_at,
            metadata,
        },
        changed,
    ))
}

fn parse_stream_subscription_lookup_id(value: &str) -> Result<StreamConsumerGroupId> {
    let (id, _) = parse_or_migrate_stream_consumer_group_id(value).map_err(|error| {
        PlatformError::invalid("invalid subscription id").with_detail(error.to_string())
    })?;
    Ok(id)
}

fn parse_or_migrate_stream_consumer_group_id(
    value: &str,
) -> std::result::Result<(StreamConsumerGroupId, bool), String> {
    match StreamConsumerGroupId::parse(value.to_owned()) {
        Ok(id) => Ok((id, false)),
        Err(stream_error) => match SubscriptionId::parse(value.to_owned()) {
            Ok(legacy) => Ok((
                stream_consumer_group_id_from_legacy_subscription_id(&legacy)?,
                true,
            )),
            Err(_) => Err(stream_error.to_string()),
        },
    }
}

fn parse_or_migrate_stream_consumer_member_id(
    value: &str,
) -> std::result::Result<(StreamConsumerMemberId, bool), String> {
    match StreamConsumerMemberId::parse(value.to_owned()) {
        Ok(id) => Ok((id, false)),
        Err(stream_error) => match SubscriptionId::parse(value.to_owned()) {
            Ok(legacy) => Ok((
                stream_consumer_member_id_from_legacy_subscription_id(&legacy)?,
                true,
            )),
            Err(_) => Err(stream_error.to_string()),
        },
    }
}

fn parse_or_migrate_stream_checkpoint_id(
    value: &str,
) -> std::result::Result<(StreamCheckpointId, bool), String> {
    match StreamCheckpointId::parse(value.to_owned()) {
        Ok(id) => Ok((id, false)),
        Err(stream_error) => match SubscriptionId::parse(value.to_owned()) {
            Ok(legacy) => Ok((
                stream_checkpoint_id_from_legacy_subscription_id(&legacy)?,
                true,
            )),
            Err(_) => Err(stream_error.to_string()),
        },
    }
}

fn stream_consumer_group_id_from_legacy_subscription_id(
    legacy: &SubscriptionId,
) -> std::result::Result<StreamConsumerGroupId, String> {
    StreamConsumerGroupId::parse(reprefix_identifier(
        legacy.as_str(),
        SubscriptionId::PREFIX,
        StreamConsumerGroupId::PREFIX,
    )?)
    .map_err(|error| error.to_string())
}

fn stream_consumer_member_id_from_legacy_subscription_id(
    legacy: &SubscriptionId,
) -> std::result::Result<StreamConsumerMemberId, String> {
    StreamConsumerMemberId::parse(reprefix_identifier(
        legacy.as_str(),
        SubscriptionId::PREFIX,
        StreamConsumerMemberId::PREFIX,
    )?)
    .map_err(|error| error.to_string())
}

fn stream_checkpoint_id_from_legacy_subscription_id(
    legacy: &SubscriptionId,
) -> std::result::Result<StreamCheckpointId, String> {
    StreamCheckpointId::parse(reprefix_identifier(
        legacy.as_str(),
        SubscriptionId::PREFIX,
        StreamCheckpointId::PREFIX,
    )?)
    .map_err(|error| error.to_string())
}

fn derive_stream_consumer_member_id(
    consumer_group_id: &StreamConsumerGroupId,
) -> std::result::Result<StreamConsumerMemberId, String> {
    StreamConsumerMemberId::parse(reprefix_identifier(
        consumer_group_id.as_str(),
        StreamConsumerGroupId::PREFIX,
        StreamConsumerMemberId::PREFIX,
    )?)
    .map_err(|error| error.to_string())
}

fn derive_stream_checkpoint_id(
    consumer_group_id: &StreamConsumerGroupId,
) -> std::result::Result<StreamCheckpointId, String> {
    StreamCheckpointId::parse(reprefix_identifier(
        consumer_group_id.as_str(),
        StreamConsumerGroupId::PREFIX,
        StreamCheckpointId::PREFIX,
    )?)
    .map_err(|error| error.to_string())
}

fn reprefix_identifier(
    value: &str,
    expected_prefix: &str,
    new_prefix: &str,
) -> std::result::Result<String, String> {
    let Some((prefix, body)) = value.split_once('_') else {
        return Err(format!("invalid identifier shape `{value}`"));
    };
    if prefix != expected_prefix {
        return Err(format!(
            "expected id prefix `{expected_prefix}`, got `{value}`",
        ));
    }
    Ok(format!("{new_prefix}_{body}"))
}

fn upsert_metadata_annotation(metadata: &mut ResourceMetadata, key: &str, value: &str) -> bool {
    match metadata.annotations.get(key) {
        Some(current) if current == value => false,
        _ => {
            metadata
                .annotations
                .insert(key.to_owned(), value.to_owned());
            true
        }
    }
}

fn upsert_subscription_metadata_annotations(
    metadata: &mut ResourceMetadata,
    subscription_id: &StreamConsumerGroupId,
    member_id: &StreamConsumerMemberId,
    checkpoint_id: &StreamCheckpointId,
) -> bool {
    let mut changed = false;
    changed |= upsert_metadata_annotation(
        metadata,
        "stream.subscription.consumer_group_id",
        subscription_id.as_str(),
    );
    changed |= upsert_metadata_annotation(
        metadata,
        "stream.subscription.member_id",
        member_id.as_str(),
    );
    changed |= upsert_metadata_annotation(
        metadata,
        "stream.subscription.checkpoint_id",
        checkpoint_id.as_str(),
    );
    changed
}

fn normalize_subscription_metadata_for_migration(
    metadata: &mut ResourceMetadata,
    subscription_id: &StreamConsumerGroupId,
    member_id: &StreamConsumerMemberId,
    checkpoint_id: &StreamCheckpointId,
    stream_id: &ManagedStreamId,
    acknowledged_offset: u64,
    lag_messages: u64,
    max_lag_messages: u64,
) -> bool {
    let mut changed = upsert_subscription_metadata_annotations(
        metadata,
        subscription_id,
        member_id,
        checkpoint_id,
    );
    let expected_etag = subscription_etag(
        subscription_id,
        member_id,
        checkpoint_id,
        stream_id,
        acknowledged_offset,
        lag_messages,
        max_lag_messages,
    );
    if metadata.etag != expected_etag {
        metadata.etag = expected_etag;
        changed = true;
    }
    changed
}

async fn write_stream_state_atomically(path: &Path, payload: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await.map_err(|error| {
            PlatformError::unavailable("failed to create stream state directory")
                .with_detail(error.to_string())
        })?;
    }
    let temp_name = format!(
        "{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("stream-state"),
        AuditId::generate()
            .map_err(|error| {
                PlatformError::unavailable("failed to allocate stream migration temp id")
                    .with_detail(error.to_string())
            })?
            .as_str(),
    );
    let temp_path = path.with_file_name(temp_name);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut temp = options.open(&temp_path).await.map_err(|error| {
        PlatformError::unavailable("failed to open stream migration temp file")
            .with_detail(error.to_string())
    })?;
    temp.write_all(payload).await.map_err(|error| {
        PlatformError::unavailable("failed to write stream migration temp file")
            .with_detail(error.to_string())
    })?;
    temp.flush().await.map_err(|error| {
        PlatformError::unavailable("failed to flush stream migration temp file")
            .with_detail(error.to_string())
    })?;
    temp.sync_all().await.map_err(|error| {
        PlatformError::unavailable("failed to sync stream migration temp file")
            .with_detail(error.to_string())
    })?;
    drop(temp);
    fs::rename(&temp_path, path).await.map_err(|error| {
        PlatformError::unavailable("failed to commit migrated stream state")
            .with_detail(error.to_string())
    })?;
    Ok(())
}

fn validate_managed_stream_id_body(body: &str) -> std::result::Result<(), ManagedStreamIdError> {
    let surrogate = format!("aud_{body}");
    AuditId::parse(surrogate)
        .map(|_| ())
        .map_err(|error| ManagedStreamIdError::invalid(error.to_string()))
}

fn build_stream_partition_record(
    stream_id: &ManagedStreamId,
    partition_index: u16,
    owner_id: Option<String>,
) -> StreamPartitionRecord {
    let mut metadata = ResourceMetadata::new(
        OwnershipScope::Tenant,
        owner_id,
        stream_partition_etag(stream_id, partition_index, 0, 0, 0),
    );
    metadata.lifecycle = ResourceLifecycleState::Ready;
    metadata.annotations.insert(
        String::from("stream.partition_index"),
        partition_index.to_string(),
    );
    StreamPartitionRecord {
        stream_id: stream_id.clone(),
        partition_index,
        latest_partition_offset: 0,
        published_messages: 0,
        published_bytes: 0,
        last_publish_at: None,
        metadata,
    }
}

fn effective_owner_id(
    request_owner_id: Option<String>,
    context: &RequestContext,
) -> Option<String> {
    request_owner_id
        .and_then(|value| {
            let trimmed = value.trim().to_owned();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .or_else(|| context.tenant_id.clone())
        .or_else(|| context.actor.clone())
}

fn normalize_stream_name(value: &str) -> Result<String> {
    normalize_human_name("stream name", value, 80)
}

fn normalize_consumer_group(value: &str) -> Result<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Err(PlatformError::invalid("consumer_group may not be empty"));
    }
    if value.len() > 80 {
        return Err(PlatformError::invalid(
            "consumer_group exceeds maximum length of 80 characters",
        ));
    }
    if value.chars().all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == '-'
            || character == '_'
            || character == '.'
    }) {
        Ok(value)
    } else {
        Err(PlatformError::invalid(
            "consumer_group may only contain [a-z0-9._-]",
        ))
    }
}

fn normalize_human_name(field: &str, value: &str, max_len: usize) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty")));
    }
    if value.len() > max_len {
        return Err(PlatformError::invalid(format!(
            "{field} exceeds maximum length of {max_len} characters",
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(PlatformError::invalid(format!(
            "{field} may not contain control characters",
        )));
    }
    Ok(value.to_owned())
}

fn normalize_storage_class(value: Option<&str>) -> Result<String> {
    let normalized = value
        .unwrap_or(DEFAULT_STORAGE_CLASS)
        .trim()
        .to_ascii_lowercase();
    match normalized.as_str() {
        "standard" | "compact" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "storage_class must be one of standard/compact",
        )),
    }
}

fn normalize_delivery_semantics(value: Option<&str>) -> Result<String> {
    let normalized = value
        .unwrap_or(DEFAULT_DELIVERY_SEMANTICS)
        .trim()
        .to_ascii_lowercase();
    match normalized.as_str() {
        "at_least_once" | "at_most_once" | "fanout" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "delivery_semantics must be one of at_least_once/at_most_once/fanout",
        )),
    }
}

fn normalize_optional_token(
    field: &str,
    value: Option<String>,
    max_len: usize,
) -> Result<Option<String>> {
    match value {
        Some(value) => {
            let value = value.trim();
            if value.is_empty() {
                Ok(None)
            } else {
                Ok(Some(normalize_human_name(field, value, max_len)?))
            }
        }
        None => Ok(None),
    }
}

fn normalize_headers(headers: BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
    let mut normalized = BTreeMap::new();
    for (key, value) in headers {
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(PlatformError::invalid("record header key may not be empty"));
        }
        if key.len() > 120 {
            return Err(PlatformError::invalid(
                "record header key exceeds maximum length of 120 characters",
            ));
        }
        if key.chars().any(char::is_control) {
            return Err(PlatformError::invalid(
                "record header key may not contain control characters",
            ));
        }
        let value = normalize_human_name("record header value", &value, 256)?;
        normalized.insert(key, value);
    }
    Ok(normalized)
}

fn validate_partition_count(partition_count: u16) -> Result<()> {
    if partition_count == 0 {
        return Err(PlatformError::invalid(
            "partition_count must be greater than zero",
        ));
    }
    if partition_count > 1024 {
        return Err(PlatformError::invalid(
            "partition_count exceeds maximum of 1024",
        ));
    }
    Ok(())
}

fn validate_retention_hours(retention_hours: u32) -> Result<()> {
    if retention_hours == 0 {
        return Err(PlatformError::invalid(
            "retention_hours must be greater than zero",
        ));
    }
    if retention_hours > 24 * 365 {
        return Err(PlatformError::invalid(
            "retention_hours exceeds maximum of 8760 hours",
        ));
    }
    Ok(())
}

fn prepare_publish_records(
    stream: &StreamRecord,
    request: &PublishStreamRequest,
    producer_id: Option<&str>,
) -> Result<Vec<PreparedPublishRecord>> {
    if !request.records.is_empty() {
        let mut prepared = Vec::with_capacity(request.records.len());
        for (index, record) in request.records.iter().enumerate() {
            let headers = normalize_headers(record.headers.clone())?;
            let key = normalize_optional_token("record key", record.key.clone(), 120)?;
            let partition_index = match record.partition {
                Some(partition) => {
                    if partition >= stream.partition_count {
                        return Err(PlatformError::invalid(format!(
                            "record partition {} is outside stream partition range",
                            partition,
                        )));
                    }
                    partition
                }
                None => route_partition(
                    key.as_deref(),
                    stream.partition_count,
                    stream
                        .latest_offset
                        .saturating_add(u64::try_from(index).map_err(|error| {
                            PlatformError::unavailable(
                                "publish record index exceeded supported u64 range",
                            )
                            .with_detail(error.to_string())
                        })?),
                ),
            };
            prepared.push(PreparedPublishRecord {
                partition_index,
                key,
                payload: record.payload.clone(),
                headers,
                byte_count: u64::try_from(record.payload.len()).map_err(|error| {
                    PlatformError::unavailable("payload length exceeded supported u64 range")
                        .with_detail(error.to_string())
                })?,
            });
        }
        return Ok(prepared);
    }

    let message_count = request.message_count.unwrap_or(0);
    if message_count == 0 {
        return Err(PlatformError::invalid(
            "publish requires non-empty records or message_count > 0",
        ));
    }
    let declared_byte_count = request.byte_count.unwrap_or(0);
    let mut prepared = Vec::with_capacity(usize::try_from(message_count).map_err(|error| {
        PlatformError::unavailable("message_count exceeded supported usize range")
            .with_detail(error.to_string())
    })?);
    for index in 0..message_count {
        let payload = format!(
            "legacy_counter_publish:{}:{}:{}",
            stream.id.as_str(),
            producer_id.unwrap_or("system"),
            index.saturating_add(1),
        );
        let byte_count =
            distribute_legacy_byte_count(declared_byte_count, message_count, index, payload.len())?;
        prepared.push(PreparedPublishRecord {
            partition_index: route_partition(
                None,
                stream.partition_count,
                stream.latest_offset.saturating_add(u64::from(index)),
            ),
            key: None,
            payload,
            headers: BTreeMap::new(),
            byte_count,
        });
    }
    Ok(prepared)
}

fn distribute_legacy_byte_count(
    declared_total: u64,
    message_count: u32,
    record_index: u32,
    fallback_payload_len: usize,
) -> Result<u64> {
    if declared_total == 0 {
        return u64::try_from(fallback_payload_len).map_err(|error| {
            PlatformError::unavailable("payload length exceeded supported u64 range")
                .with_detail(error.to_string())
        });
    }
    let divisor = u64::from(message_count);
    let base = declared_total / divisor;
    let remainder = declared_total % divisor;
    let receives_extra_byte = record_index < u32::try_from(remainder).unwrap_or(u32::MAX);
    Ok(base + if receives_extra_byte { 1 } else { 0 })
}

fn route_partition(key: Option<&str>, partition_count: u16, seed_offset: u64) -> u16 {
    match key {
        Some(key) => {
            let digest = sha256_hex(key.as_bytes());
            let folded = digest.bytes().fold(0_u64, |accumulator, byte| {
                accumulator.wrapping_mul(131).wrapping_add(u64::from(byte))
            });
            (folded % u64::from(partition_count)) as u16
        }
        None => (seed_offset % u64::from(partition_count)) as u16,
    }
}

fn parse_optional_partition_query(
    value: Option<&String>,
    partition_count: u16,
) -> Result<Option<u16>> {
    match value {
        Some(value) => {
            let parsed = value.parse::<u16>().map_err(|error| {
                PlatformError::invalid("partition must be a valid u16")
                    .with_detail(error.to_string())
            })?;
            if parsed >= partition_count {
                return Err(PlatformError::invalid(format!(
                    "partition {} is outside stream partition range",
                    parsed,
                )));
            }
            Ok(Some(parsed))
        }
        None => Ok(None),
    }
}

fn parse_replay_after_offset(value: Option<&String>) -> Result<u64> {
    match value {
        Some(value) => value.parse::<u64>().map_err(|error| {
            PlatformError::invalid("after_offset must be a valid u64")
                .with_detail(error.to_string())
        }),
        None => Ok(0),
    }
}

fn parse_replay_limit(value: Option<&String>) -> Result<usize> {
    let limit = match value {
        Some(value) => value.parse::<usize>().map_err(|error| {
            PlatformError::invalid("limit must be a valid usize").with_detail(error.to_string())
        })?,
        None => DEFAULT_REPLAY_LIMIT,
    };
    if limit == 0 {
        return Err(PlatformError::invalid("limit must be greater than zero"));
    }
    Ok(limit.min(MAX_REPLAY_LIMIT))
}

fn partition_key(stream_id: &ManagedStreamId, partition_index: u16) -> String {
    format!("{}:{partition_index:04}", stream_id.as_str())
}

fn stream_log_key(
    stream_id: &ManagedStreamId,
    partition_index: u16,
    partition_offset: u64,
) -> String {
    format!(
        "{}:{partition_index:04}:{partition_offset:020}",
        stream_id.as_str()
    )
}

fn stream_etag(
    stream_id: &ManagedStreamId,
    latest_offset: u64,
    published_messages: u64,
    published_bytes: u64,
) -> String {
    sha256_hex(
        format!(
            "{}:{latest_offset}:{published_messages}:{published_bytes}",
            stream_id.as_str()
        )
        .as_bytes(),
    )
}

fn stream_partition_etag(
    stream_id: &ManagedStreamId,
    partition_index: u16,
    latest_partition_offset: u64,
    published_messages: u64,
    published_bytes: u64,
) -> String {
    sha256_hex(
        format!(
            "{}:{partition_index}:{latest_partition_offset}:{published_messages}:{published_bytes}",
            stream_id.as_str(),
        )
        .as_bytes(),
    )
}

fn stream_log_etag(
    entry_id: &AuditId,
    stream_id: &ManagedStreamId,
    stream_offset: u64,
    partition_index: u16,
    partition_offset: u64,
    byte_count: u64,
) -> String {
    sha256_hex(
        format!(
            "{}:{}:{stream_offset}:{partition_index}:{partition_offset}:{byte_count}",
            entry_id.as_str(),
            stream_id.as_str(),
        )
        .as_bytes(),
    )
}

fn subscription_etag(
    subscription_id: &StreamConsumerGroupId,
    member_id: &StreamConsumerMemberId,
    checkpoint_id: &StreamCheckpointId,
    stream_id: &ManagedStreamId,
    acknowledged_offset: u64,
    lag_messages: u64,
    max_lag_messages: u64,
) -> String {
    sha256_hex(
        format!(
            "{}:{}:{}:{}:{acknowledged_offset}:{lag_messages}:{max_lag_messages}",
            subscription_id.as_str(),
            member_id.as_str(),
            checkpoint_id.as_str(),
            stream_id.as_str(),
        )
        .as_bytes(),
    )
}

fn stream_lag_summary_etag(summary: &StreamLagSummary) -> String {
    sha256_hex(
        format!(
            "{}:{}:{}:{}:{}:{}",
            summary.stream_id.as_str(),
            summary.partition_count,
            summary.latest_offset,
            summary.subscription_count,
            summary.total_lag_messages,
            summary.max_lag_messages,
        )
        .as_bytes(),
    )
}

fn stream_partitions_etag(
    stream_id: &ManagedStreamId,
    partitions: &[StreamPartitionRecord],
) -> String {
    sha256_hex(
        format!(
            "{}:{}",
            stream_id.as_str(),
            partitions
                .iter()
                .map(|partition| format!(
                    "{}:{}:{}",
                    partition.partition_index,
                    partition.latest_partition_offset,
                    partition.published_messages
                ))
                .collect::<Vec<_>>()
                .join("|")
        )
        .as_bytes(),
    )
}

fn replay_page_etag(page: &StreamReplayPage) -> String {
    sha256_hex(
        format!(
            "{}:{}:{}:{}:{}:{}",
            page.stream_id.as_str(),
            page.partition
                .map(|partition| partition.to_string())
                .unwrap_or_else(|| String::from("all")),
            page.after_offset,
            page.stream_high_watermark,
            page.partition_high_watermark.unwrap_or(0),
            page.items
                .iter()
                .map(|record| record.id.as_str())
                .collect::<Vec<_>>()
                .join("|"),
        )
        .as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use http::header::ETAG;
    use http::{Response, StatusCode};
    use http_body_util::BodyExt;
    use serde::de::DeserializeOwned;
    use tempfile::tempdir;
    use time::OffsetDateTime;
    use uhost_api::ApiBody;
    use uhost_core::RequestContext;
    use uhost_store::{DocumentChange, DocumentCollection, StoredDocument};
    use uhost_types::id::{StreamCheckpointId, StreamConsumerGroupId, StreamConsumerMemberId};
    use uhost_types::{OwnershipScope, ResourceLifecycleState, ResourceMetadata, SubscriptionId};

    use super::{
        AcknowledgeSubscriptionRequest, CreateStreamRequest, CreateSubscriptionRequest,
        ManagedStreamId, PublishRecordRequest, PublishStreamRequest, StreamLagSummary,
        StreamPublishResponse, StreamRecord, StreamReplayPage, StreamService, StreamServiceSummary,
        SubscriptionRecord, SubscriptionRecordCompatibility, parse_stream_subscription_lookup_id,
        subscription_etag, write_stream_state_atomically,
    };

    fn context() -> RequestContext {
        RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("stream.operator")
            .with_tenant("tenant-alpha")
    }

    async fn read_json<T>(response: Response<ApiBody>) -> T
    where
        T: DeserializeOwned,
    {
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"))
    }

    fn replay_query(
        limit: usize,
        partition: Option<u16>,
        after_offset: u64,
    ) -> BTreeMap<String, String> {
        let mut query = BTreeMap::new();
        query.insert(String::from("limit"), limit.to_string());
        query.insert(String::from("after_offset"), after_offset.to_string());
        if let Some(partition) = partition {
            query.insert(String::from("partition"), partition.to_string());
        }
        query
    }

    fn id_body(value: &str) -> &str {
        value
            .split_once('_')
            .map(|(_, body)| body)
            .unwrap_or_else(|| panic!("invalid id shape `{value}`"))
    }

    #[tokio::test]
    async fn stream_and_partition_state_persist_across_reopen() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StreamService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = context();

        let created_stream = service
            .create_stream(
                CreateStreamRequest {
                    name: String::from("orders"),
                    partition_count: Some(3),
                    retention_hours: Some(96),
                    storage_class: Some(String::from("standard")),
                    owner_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created_stream.status(), StatusCode::CREATED);
        assert!(created_stream.headers().contains_key(ETAG));
        let stream: StreamRecord = read_json(created_stream).await;
        assert!(stream.id.as_str().starts_with("stm_"));

        let publish: StreamPublishResponse = read_json(
            service
                .publish_stream(
                    stream.id.as_str(),
                    PublishStreamRequest {
                        records: vec![
                            PublishRecordRequest {
                                partition: Some(0),
                                key: Some(String::from("tenant-a")),
                                payload: String::from("alpha"),
                                headers: BTreeMap::from([(
                                    String::from("content-type"),
                                    String::from("text/plain"),
                                )]),
                            },
                            PublishRecordRequest {
                                partition: Some(2),
                                key: Some(String::from("tenant-b")),
                                payload: String::from("bravo"),
                                headers: BTreeMap::new(),
                            },
                        ],
                        message_count: None,
                        byte_count: None,
                        producer_id: Some(String::from("producer-a")),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(publish.stream.latest_offset, 2);
        assert_eq!(publish.appended_records.len(), 2);

        let reopened = StreamService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let streams = reopened
            .list_active_streams()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].id, stream.id);
        assert_eq!(streams[0].latest_offset, 2);

        let partitions = reopened
            .list_active_partitions(Some(stream.id.as_str()))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(partitions.len(), 3);
        assert_eq!(partitions[0].latest_partition_offset, 1);
        assert_eq!(partitions[2].latest_partition_offset, 1);

        let replay = reopened
            .stream_replay_response(stream.id.as_str(), &replay_query(10, None, 0))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replay_page: StreamReplayPage = read_json(replay).await;
        assert_eq!(replay_page.items.len(), 2);
        assert_eq!(replay_page.items[0].payload, "alpha");
        assert_eq!(replay_page.items[1].payload, "bravo");
    }

    #[tokio::test]
    async fn publish_materializes_partitioned_log_and_replay_pages() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StreamService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = context();

        let stream: StreamRecord = read_json(
            service
                .create_stream(
                    CreateStreamRequest {
                        name: String::from("events"),
                        partition_count: Some(4),
                        retention_hours: None,
                        storage_class: Some(String::from("compact")),
                        owner_id: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let subscription_a: SubscriptionRecord = read_json(
            service
                .create_subscription(
                    CreateSubscriptionRequest {
                        stream_id: stream.id.to_string(),
                        consumer_group: String::from("realtime"),
                        delivery_semantics: Some(String::from("fanout")),
                        initial_offset: Some(0),
                        max_lag_messages: Some(10),
                        owner_id: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let _subscription_b: SubscriptionRecord = read_json(
            service
                .create_subscription(
                    CreateSubscriptionRequest {
                        stream_id: stream.id.to_string(),
                        consumer_group: String::from("warehouse"),
                        delivery_semantics: None,
                        initial_offset: Some(0),
                        max_lag_messages: Some(500),
                        owner_id: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let published: StreamPublishResponse = read_json(
            service
                .publish_stream(
                    stream.id.as_str(),
                    PublishStreamRequest {
                        records: vec![
                            PublishRecordRequest {
                                partition: Some(0),
                                key: Some(String::from("acct-1")),
                                payload: String::from("one"),
                                headers: BTreeMap::new(),
                            },
                            PublishRecordRequest {
                                partition: Some(0),
                                key: Some(String::from("acct-2")),
                                payload: String::from("two"),
                                headers: BTreeMap::new(),
                            },
                            PublishRecordRequest {
                                partition: Some(3),
                                key: Some(String::from("acct-3")),
                                payload: String::from("three"),
                                headers: BTreeMap::new(),
                            },
                        ],
                        message_count: None,
                        byte_count: None,
                        producer_id: Some(String::from("producer-a")),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(published.stream.latest_offset, 3);
        assert_eq!(published.stream.published_messages, 3);
        assert_eq!(published.appended_records.len(), 3);
        assert_eq!(published.appended_records[0].stream_offset, 1);
        assert_eq!(published.appended_records[1].partition_offset, 2);
        assert_eq!(published.appended_records[2].partition_index, 3);

        let partition_zero_replay: StreamReplayPage = read_json(
            service
                .stream_replay_response(stream.id.as_str(), &replay_query(10, Some(0), 0))
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(partition_zero_replay.partition, Some(0));
        assert_eq!(partition_zero_replay.partition_high_watermark, Some(2));
        assert_eq!(partition_zero_replay.items.len(), 2);
        assert_eq!(partition_zero_replay.items[0].partition_offset, 1);
        assert_eq!(partition_zero_replay.items[1].partition_offset, 2);

        let lag_summary = service
            .stream_lag_summary(stream.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing lag summary"));
        assert_eq!(
            lag_summary,
            StreamLagSummary {
                stream_id: stream.id.clone(),
                stream_name: String::from("events"),
                partition_count: 4,
                latest_offset: 3,
                published_messages: 3,
                published_bytes: 11,
                last_publish_at: published.stream.last_publish_at,
                subscription_count: 2,
                healthy_subscription_count: 2,
                total_lag_messages: 6,
                max_lag_messages: 3,
            }
        );

        let acknowledged: SubscriptionRecord = read_json(
            service
                .acknowledge_subscription(
                    subscription_a.id.as_str(),
                    AcknowledgeSubscriptionRequest {
                        acknowledged_offset: 2,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(acknowledged.acknowledged_offset, 2);
        assert_eq!(acknowledged.lag_messages, 1);
        assert!(acknowledged.healthy);

        let summary = service
            .service_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            summary,
            StreamServiceSummary {
                stream_count: 1,
                partition_count: 4,
                subscription_count: 2,
                idle_stream_count: 0,
                lagging_stream_count: 1,
                unhealthy_subscription_count: 0,
                total_published_messages: 3,
                total_published_bytes: 11,
                total_retained_records: 3,
                total_retained_record_bytes: 11,
                total_lag_messages: 4,
            }
        );

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(outbox.len(), 5);
        assert!(
            outbox
                .iter()
                .all(|message| message.topic == "stream.events.v1")
        );
    }

    #[tokio::test]
    async fn legacy_counter_publish_now_materializes_replayable_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StreamService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = context();

        let stream: StreamRecord = read_json(
            service
                .create_stream(
                    CreateStreamRequest {
                        name: String::from("legacy"),
                        partition_count: Some(2),
                        retention_hours: None,
                        storage_class: None,
                        owner_id: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let published: StreamPublishResponse = read_json(
            service
                .publish_stream(
                    stream.id.as_str(),
                    PublishStreamRequest {
                        records: Vec::new(),
                        message_count: Some(5),
                        byte_count: Some(50),
                        producer_id: Some(String::from("legacy-producer")),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(published.stream.latest_offset, 5);
        assert_eq!(published.stream.published_messages, 5);
        assert_eq!(published.stream.published_bytes, 50);
        assert_eq!(published.appended_records.len(), 5);
        assert!(
            published
                .appended_records
                .iter()
                .all(|record| record.payload.starts_with("legacy_counter_publish"))
        );

        let replay: StreamReplayPage = read_json(
            service
                .stream_replay_response(stream.id.as_str(), &replay_query(10, None, 0))
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(replay.items.len(), 5);
        assert_eq!(replay.stream_high_watermark, 5);
    }

    #[tokio::test]
    async fn reopen_reconciles_stream_projection_back_to_zero_when_log_is_empty() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StreamService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = context();

        let stream: StreamRecord = read_json(
            service
                .create_stream(
                    CreateStreamRequest {
                        name: String::from("reconcile-reset"),
                        partition_count: Some(2),
                        retention_hours: None,
                        storage_class: None,
                        owner_id: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let _subscription: SubscriptionRecord = read_json(
            service
                .create_subscription(
                    CreateSubscriptionRequest {
                        stream_id: stream.id.to_string(),
                        consumer_group: String::from("ops"),
                        delivery_semantics: None,
                        initial_offset: Some(0),
                        max_lag_messages: Some(10),
                        owner_id: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let _published: StreamPublishResponse = read_json(
            service
                .publish_stream(
                    stream.id.as_str(),
                    PublishStreamRequest {
                        records: vec![
                            PublishRecordRequest {
                                partition: Some(0),
                                key: Some(String::from("acct-a")),
                                payload: String::from("alpha"),
                                headers: BTreeMap::new(),
                            },
                            PublishRecordRequest {
                                partition: Some(1),
                                key: Some(String::from("acct-b")),
                                payload: String::from("bravo"),
                                headers: BTreeMap::new(),
                            },
                        ],
                        message_count: None,
                        byte_count: None,
                        producer_id: Some(String::from("producer-a")),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let log_entries = service
            .log_entries
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(log_entries.len(), 2);
        for (key, stored) in log_entries {
            service
                .log_entries
                .soft_delete(&key, Some(stored.version))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let reopened = StreamService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let streams = reopened
            .list_active_streams()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].latest_offset, 0);
        assert_eq!(streams[0].published_messages, 0);
        assert_eq!(streams[0].published_bytes, 0);
        assert_eq!(streams[0].last_publish_at, None);

        let partitions = reopened
            .list_active_partitions(Some(stream.id.as_str()))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(partitions.len(), 2);
        assert!(partitions.iter().all(|partition| {
            partition.latest_partition_offset == 0
                && partition.published_messages == 0
                && partition.published_bytes == 0
                && partition.last_publish_at.is_none()
        }));

        let subscriptions = reopened
            .list_active_subscriptions(Some(stream.id.as_str()), Some("ops"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(subscriptions.len(), 1);
        assert_eq!(subscriptions[0].acknowledged_offset, 0);
        assert_eq!(subscriptions[0].lag_messages, 0);
        assert!(subscriptions[0].healthy);
    }

    #[tokio::test]
    async fn validation_and_monotonic_ack_rules_are_enforced() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StreamService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = context();

        let create_error = service
            .create_stream(
                CreateStreamRequest {
                    name: String::from(" "),
                    partition_count: Some(1),
                    retention_hours: None,
                    storage_class: None,
                    owner_id: None,
                },
                &context,
            )
            .await
            .expect_err("expected empty stream name to fail");
        assert!(create_error.to_string().contains("stream name"));

        let stream: StreamRecord = read_json(
            service
                .create_stream(
                    CreateStreamRequest {
                        name: String::from("audit"),
                        partition_count: Some(1),
                        retention_hours: None,
                        storage_class: None,
                        owner_id: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert!(ManagedStreamId::parse(stream.id.to_string()).is_ok());

        let subscription: SubscriptionRecord = read_json(
            service
                .create_subscription(
                    CreateSubscriptionRequest {
                        stream_id: stream.id.to_string(),
                        consumer_group: String::from("ops"),
                        delivery_semantics: None,
                        initial_offset: Some(0),
                        max_lag_messages: Some(100),
                        owner_id: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let publish_error = service
            .publish_stream(
                stream.id.as_str(),
                PublishStreamRequest {
                    records: vec![PublishRecordRequest {
                        partition: Some(9),
                        key: None,
                        payload: String::from("bad"),
                        headers: BTreeMap::new(),
                    }],
                    message_count: None,
                    byte_count: None,
                    producer_id: None,
                },
                &context,
            )
            .await
            .expect_err("expected out-of-range partition to fail");
        assert!(
            publish_error
                .to_string()
                .contains("outside stream partition range")
        );

        let _ = service
            .publish_stream(
                stream.id.as_str(),
                PublishStreamRequest {
                    records: vec![PublishRecordRequest {
                        partition: Some(0),
                        key: None,
                        payload: String::from("ok"),
                        headers: BTreeMap::new(),
                    }],
                    message_count: None,
                    byte_count: None,
                    producer_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let ahead_error = service
            .acknowledge_subscription(
                subscription.id.as_str(),
                AcknowledgeSubscriptionRequest {
                    acknowledged_offset: 9,
                },
                &context,
            )
            .await
            .expect_err("expected ahead-of-stream ack to fail");
        assert!(
            ahead_error
                .to_string()
                .contains("ahead of the current stream offset")
        );

        let _ = service
            .acknowledge_subscription(
                subscription.id.as_str(),
                AcknowledgeSubscriptionRequest {
                    acknowledged_offset: 1,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let rewind_error = service
            .acknowledge_subscription(
                subscription.id.as_str(),
                AcknowledgeSubscriptionRequest {
                    acknowledged_offset: 0,
                },
                &context,
            )
            .await
            .expect_err("expected rewind ack to fail");
        assert!(rewind_error.to_string().contains("move backwards"));
    }

    #[tokio::test]
    async fn create_subscription_allocates_dedicated_stream_family_ids() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StreamService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = context();

        let stream: StreamRecord = read_json(
            service
                .create_stream(
                    CreateStreamRequest {
                        name: String::from("consumer-ids"),
                        partition_count: Some(1),
                        retention_hours: None,
                        storage_class: None,
                        owner_id: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let subscription: SubscriptionRecord = read_json(
            service
                .create_subscription(
                    CreateSubscriptionRequest {
                        stream_id: stream.id.to_string(),
                        consumer_group: String::from("analytics"),
                        delivery_semantics: None,
                        initial_offset: Some(0),
                        max_lag_messages: Some(100),
                        owner_id: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        assert!(StreamConsumerGroupId::parse(subscription.id.to_string()).is_ok());
        assert!(StreamConsumerMemberId::parse(subscription.member_id.to_string()).is_ok());
        assert!(StreamCheckpointId::parse(subscription.checkpoint_id.to_string()).is_ok());
        assert!(SubscriptionId::parse(subscription.id.to_string()).is_err());
        assert!(SubscriptionId::parse(subscription.member_id.to_string()).is_err());
        assert!(SubscriptionId::parse(subscription.checkpoint_id.to_string()).is_err());
        assert_ne!(subscription.id.as_str(), subscription.member_id.as_str());
        assert_ne!(
            subscription.id.as_str(),
            subscription.checkpoint_id.as_str()
        );
        assert_ne!(
            subscription
                .metadata
                .annotations
                .get("stream.subscription.consumer_group_id"),
            None
        );
        assert_eq!(
            subscription
                .metadata
                .annotations
                .get("stream.subscription.consumer_group_id")
                .map(String::as_str),
            Some(subscription.id.as_str())
        );
        assert_eq!(
            subscription
                .metadata
                .annotations
                .get("stream.subscription.member_id")
                .map(String::as_str),
            Some(subscription.member_id.as_str())
        );
        assert_eq!(
            subscription
                .metadata
                .annotations
                .get("stream.subscription.checkpoint_id")
                .map(String::as_str),
            Some(subscription.checkpoint_id.as_str())
        );
        assert_eq!(
            parse_stream_subscription_lookup_id(subscription.id.as_str())
                .unwrap_or_else(|error| panic!("{error}")),
            subscription.id
        );
    }

    #[tokio::test]
    async fn reopen_migrates_legacy_subscription_ids_and_accepts_legacy_lookup() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StreamService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = context();

        let stream: StreamRecord = read_json(
            service
                .create_stream(
                    CreateStreamRequest {
                        name: String::from("legacy-subscription-ids"),
                        partition_count: Some(1),
                        retention_hours: None,
                        storage_class: None,
                        owner_id: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let fresh_subscription: SubscriptionRecord = read_json(
            service
                .create_subscription(
                    CreateSubscriptionRequest {
                        stream_id: stream.id.to_string(),
                        consumer_group: String::from("ops"),
                        delivery_semantics: None,
                        initial_offset: Some(0),
                        max_lag_messages: Some(50),
                        owner_id: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let stored = service
            .subscriptions
            .get(fresh_subscription.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored subscription"));

        let legacy_id = SubscriptionId::generate().unwrap_or_else(|error| panic!("{error}"));
        let legacy_value = SubscriptionRecordCompatibility {
            id: legacy_id.to_string(),
            member_id: None,
            checkpoint_id: None,
            stream_id: fresh_subscription.stream_id.clone(),
            consumer_group: fresh_subscription.consumer_group.clone(),
            delivery_semantics: fresh_subscription.delivery_semantics.clone(),
            acknowledged_offset: fresh_subscription.acknowledged_offset,
            lag_messages: fresh_subscription.lag_messages,
            max_lag_messages: fresh_subscription.max_lag_messages,
            healthy: fresh_subscription.healthy,
            last_acknowledged_at: fresh_subscription.last_acknowledged_at,
            metadata: fresh_subscription.metadata.clone(),
        };
        let legacy_stored = StoredDocument {
            version: stored.version,
            updated_at: stored.updated_at,
            deleted: false,
            value: legacy_value.clone(),
        };
        let legacy_collection = DocumentCollection {
            schema_version: 1,
            revision: 1,
            compacted_through_revision: 0,
            records: BTreeMap::from([(legacy_id.to_string(), legacy_stored.clone())]),
            changes: vec![DocumentChange {
                revision: 1,
                key: legacy_id.to_string(),
                document: legacy_stored,
            }],
        };
        write_stream_state_atomically(
            temp.path().join("stream/subscriptions.json").as_path(),
            &serde_json::to_vec(&legacy_collection).unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        drop(service);

        let reopened = StreamService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let subscriptions = reopened
            .list_active_subscriptions(Some(stream.id.as_str()), Some("ops"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(subscriptions.len(), 1);
        let migrated = &subscriptions[0];
        assert_eq!(id_body(migrated.id.as_str()), id_body(legacy_id.as_str()));
        assert_eq!(
            id_body(migrated.member_id.as_str()),
            id_body(legacy_id.as_str())
        );
        assert_eq!(
            id_body(migrated.checkpoint_id.as_str()),
            id_body(legacy_id.as_str())
        );
        assert!(migrated.id.as_str().starts_with("scg_"));
        assert!(migrated.member_id.as_str().starts_with("scm_"));
        assert!(migrated.checkpoint_id.as_str().starts_with("sck_"));
        assert_eq!(
            migrated
                .metadata
                .annotations
                .get("stream.subscription.consumer_group_id")
                .map(String::as_str),
            Some(migrated.id.as_str())
        );
        assert_eq!(
            migrated
                .metadata
                .annotations
                .get("stream.subscription.member_id")
                .map(String::as_str),
            Some(migrated.member_id.as_str())
        );
        assert_eq!(
            migrated
                .metadata
                .annotations
                .get("stream.subscription.checkpoint_id")
                .map(String::as_str),
            Some(migrated.checkpoint_id.as_str())
        );
        assert!(
            reopened
                .subscriptions
                .get(legacy_id.as_str())
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );

        let looked_up: Option<SubscriptionRecord> = read_json(
            reopened
                .get_subscription_response(legacy_id.as_str())
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(
            looked_up.as_ref().map(|record| record.id.clone()),
            Some(migrated.id.clone())
        );

        let acknowledged: SubscriptionRecord = read_json(
            reopened
                .acknowledge_subscription(
                    legacy_id.as_str(),
                    AcknowledgeSubscriptionRequest {
                        acknowledged_offset: 0,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        assert_eq!(acknowledged.id, migrated.id);
        assert_eq!(
            parse_stream_subscription_lookup_id(legacy_id.as_str())
                .unwrap_or_else(|error| panic!("{error}")),
            migrated.id
        );
    }

    #[tokio::test]
    async fn migrate_legacy_subscription_etag_without_stream_reconcile() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let legacy_id = SubscriptionId::generate().unwrap_or_else(|error| panic!("{error}"));
        let stream_id = ManagedStreamId::generate().unwrap_or_else(|error| panic!("{error}"));
        let legacy_metadata = ResourceMetadata {
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            lifecycle: ResourceLifecycleState::Ready,
            ownership_scope: OwnershipScope::Tenant,
            owner_id: Some(String::from("tenant-alpha")),
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            deleted_at: None,
            etag: String::from("legacy-stale-etag"),
        };
        let legacy_updated_at = legacy_metadata.updated_at;
        let legacy_value = SubscriptionRecordCompatibility {
            id: legacy_id.to_string(),
            member_id: None,
            checkpoint_id: None,
            stream_id,
            consumer_group: String::from("ops"),
            delivery_semantics: String::from("at_least_once"),
            acknowledged_offset: 7,
            lag_messages: 3,
            max_lag_messages: 10,
            healthy: true,
            last_acknowledged_at: None,
            metadata: legacy_metadata,
        };
        let legacy_collection = DocumentCollection {
            schema_version: 1,
            revision: 1,
            compacted_through_revision: 0,
            records: BTreeMap::from([(
                legacy_id.to_string(),
                StoredDocument {
                    version: 1,
                    updated_at: OffsetDateTime::now_utc(),
                    deleted: false,
                    value: legacy_value.clone(),
                },
            )]),
            changes: vec![DocumentChange {
                revision: 1,
                key: legacy_id.to_string(),
                document: StoredDocument {
                    version: 1,
                    updated_at: OffsetDateTime::now_utc(),
                    deleted: false,
                    value: legacy_value,
                },
            }],
        };
        write_stream_state_atomically(
            temp.path().join("stream/subscriptions.json").as_path(),
            &serde_json::to_vec(&legacy_collection).unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let reopened = StreamService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let subscriptions = reopened
            .list_active_subscriptions(None, Some("ops"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(subscriptions.len(), 1);
        let migrated = &subscriptions[0];
        assert_ne!(migrated.metadata.etag, "legacy-stale-etag");
        assert_eq!(migrated.metadata.updated_at, legacy_updated_at);
        assert_eq!(
            migrated.metadata.etag,
            subscription_etag(
                &migrated.id,
                &migrated.member_id,
                &migrated.checkpoint_id,
                &migrated.stream_id,
                migrated.acknowledged_offset,
                migrated.lag_messages,
                migrated.max_lag_messages,
            )
        );
        assert_eq!(
            migrated
                .metadata
                .annotations
                .get("stream.subscription.consumer_group_id")
                .map(String::as_str),
            Some(migrated.id.as_str())
        );
        assert_eq!(
            migrated
                .metadata
                .annotations
                .get("stream.subscription.member_id")
                .map(String::as_str),
            Some(migrated.member_id.as_str())
        );
        assert_eq!(
            migrated
                .metadata
                .annotations
                .get("stream.subscription.checkpoint_id")
                .map(String::as_str),
            Some(migrated.checkpoint_id.as_str())
        );
    }

    #[tokio::test]
    async fn soft_deleted_stream_is_hidden_and_blocks_new_subscriptions() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = StreamService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = context();

        let stream: StreamRecord = read_json(
            service
                .create_stream(
                    CreateStreamRequest {
                        name: String::from("retired"),
                        partition_count: Some(2),
                        retention_hours: Some(24),
                        storage_class: None,
                        owner_id: None,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let stored = service
            .streams
            .get(stream.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored stream"));
        service
            .streams
            .soft_delete(stream.id.as_str(), Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let streams = service
            .list_active_streams()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(streams.is_empty());

        let get_response = service
            .get_stream_response(stream.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload: Option<StreamRecord> = read_json(get_response).await;
        assert!(payload.is_none());

        let error = service
            .create_subscription(
                CreateSubscriptionRequest {
                    stream_id: stream.id.to_string(),
                    consumer_group: String::from("late-joiner"),
                    delivery_semantics: None,
                    initial_offset: Some(0),
                    max_lag_messages: None,
                    owner_id: None,
                },
                &context,
            )
            .await
            .expect_err("expected deleted stream to reject subscriptions");
        assert!(error.to_string().contains("stream does not exist"));
    }
}
