//! Reusable lease-backed registration collection abstractions.
//!
//! Phase 1 keeps registration, readiness, drain, and lease state file-backed via
//! [`DocumentStore<T>`](crate::document::DocumentStore) while introducing a
//! narrow reusable substrate that later distribution lanes can build on without
//! coupling directly to one concrete adapter.

use std::fmt;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use uhost_core::{PlatformError, Result, sha256_hex};

use crate::document::{
    DocumentChange, DocumentChangePage, DocumentCursor, DocumentSnapshotCheckpoint, DocumentStore,
    StoredDocument,
};

/// Boxed future returned by lease-registration backends.
pub type LeaseResultFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Stable cursor used to consume deterministic lease-registration changes.
pub type LeaseRegistrationCursor = DocumentCursor;

/// One deterministic lease-registration mutation snapshot.
pub type LeaseRegistrationChange = DocumentChange<LeaseRegistrationRecord>;

/// One ordered page of deterministic lease-registration changes.
pub type LeaseRegistrationChangePage = DocumentChangePage<LeaseRegistrationRecord>;

/// Point-in-time checkpoint used to reseed lease-registration consumers after
/// change-feed compaction.
pub type LeaseRegistrationSnapshotCheckpoint = DocumentSnapshotCheckpoint<LeaseRegistrationRecord>;

/// Readiness state published by one durable registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LeaseReadiness {
    /// Registration exists but is not yet ready to serve.
    #[default]
    Starting,
    /// Registration is ready to serve.
    Ready,
}

/// Drain intent carried by one durable registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LeaseDrainIntent {
    /// Registration is serving normally.
    #[default]
    Serving,
    /// Registration intends to drain and stop serving.
    Draining,
}

/// Freshness state derived from a durable lease window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseFreshness {
    /// The lease has ample time remaining.
    Fresh,
    /// The lease is nearing expiration and should be renewed.
    Stale,
    /// The lease has expired.
    Expired,
}

/// Durable registration record backed by a renewable lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRegistrationRecord {
    /// Stable registration identifier.
    pub registration_id: String,
    /// Broad subject family (`runtime_process`, `service_shard`, etc.).
    pub subject_kind: String,
    /// Stable subject identifier.
    pub subject_id: String,
    /// Role or ownership label carried by this registration.
    pub role: String,
    /// Optional node name associated with the registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// Published readiness state.
    #[serde(default)]
    pub readiness: LeaseReadiness,
    /// Published drain intent.
    #[serde(default)]
    pub drain_intent: LeaseDrainIntent,
    /// Timestamp when the current registration incarnation was published.
    pub registered_at: OffsetDateTime,
    /// Monotonic incarnation number rotated whenever a new holder claims this registration.
    #[serde(default = "default_lease_registration_incarnation")]
    pub incarnation: u64,
    /// Stable fencing token that must accompany renewals and destructive mutation.
    #[serde(default)]
    pub fencing_token: String,
    /// Timestamp of the most recent successful lease renewal.
    pub lease_renewed_at: OffsetDateTime,
    /// Requested lease duration in whole seconds.
    pub lease_duration_seconds: u32,
    /// Timestamp when the lease expires if not renewed again.
    pub lease_expires_at: OffsetDateTime,
}

impl LeaseRegistrationRecord {
    /// Create a new registration with a fresh lease window.
    pub fn new(
        registration_id: impl Into<String>,
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        role: impl Into<String>,
        node_name: Option<String>,
        lease_duration_seconds: u32,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        let lease_duration_seconds = normalized_lease_duration_seconds(lease_duration_seconds);
        let mut record = Self {
            registration_id: registration_id.into(),
            subject_kind: subject_kind.into(),
            subject_id: subject_id.into(),
            role: role.into(),
            node_name,
            readiness: LeaseReadiness::Starting,
            drain_intent: LeaseDrainIntent::Serving,
            registered_at: now,
            incarnation: default_lease_registration_incarnation(),
            fencing_token: String::new(),
            lease_renewed_at: now,
            lease_duration_seconds,
            lease_expires_at: now + lease_duration(lease_duration_seconds),
        };
        record.begin_new_incarnation_at(now, default_lease_registration_incarnation());
        record
    }

    /// Attach a readiness state when constructing a record.
    pub fn with_readiness(mut self, readiness: LeaseReadiness) -> Self {
        self.readiness = readiness;
        self
    }

    /// Attach a drain intent when constructing a record.
    pub fn with_drain_intent(mut self, drain_intent: LeaseDrainIntent) -> Self {
        self.drain_intent = drain_intent;
        self
    }

    /// Update the readiness state in place.
    pub fn set_readiness(&mut self, readiness: LeaseReadiness) {
        self.readiness = readiness;
    }

    /// Update the drain intent in place.
    pub fn set_drain_intent(&mut self, drain_intent: LeaseDrainIntent) {
        self.drain_intent = drain_intent;
    }

    /// Renew the lease using the configured duration.
    pub fn renew(&mut self) {
        let now = OffsetDateTime::now_utc();
        self.lease_renewed_at = now;
        self.lease_expires_at = now + lease_duration(self.lease_duration_seconds);
    }

    /// Expire the lease immediately.
    pub fn expire_now(&mut self) {
        let now = OffsetDateTime::now_utc();
        self.lease_renewed_at = now;
        self.lease_expires_at = now;
    }

    /// Compute lease freshness at the provided time.
    pub fn lease_freshness_at(&self, now: OffsetDateTime) -> LeaseFreshness {
        if now >= self.lease_expires_at {
            return LeaseFreshness::Expired;
        }

        let remaining = self.lease_expires_at - now;
        if remaining <= stale_window(self.lease_duration_seconds) {
            LeaseFreshness::Stale
        } else {
            LeaseFreshness::Fresh
        }
    }

    fn begin_new_incarnation_at(&mut self, now: OffsetDateTime, incarnation: u64) {
        self.incarnation = normalized_lease_registration_incarnation(incarnation);
        self.lease_duration_seconds =
            normalized_lease_duration_seconds(self.lease_duration_seconds);
        self.registered_at = now;
        self.lease_renewed_at = now;
        self.lease_expires_at = now + lease_duration(self.lease_duration_seconds);
        self.fencing_token = lease_fencing_token(
            self.registration_id.as_str(),
            self.incarnation,
            self.registered_at,
        );
    }

    fn assert_fencing_token(&self, fencing_token: &str) -> Result<()> {
        if self.fencing_token.is_empty() {
            return Err(
                PlatformError::conflict("lease registration is missing a fencing token")
                    .with_detail("claim a new registration incarnation before mutating"),
            );
        }
        if self.fencing_token != fencing_token {
            return Err(
                PlatformError::conflict("lease fencing token does not match")
                    .with_detail("claim a new registration incarnation before mutating"),
            );
        }
        Ok(())
    }
}

/// Shared trait for durable lease-backed registrations.
pub trait LeaseRegistrationStore: Send + Sync + 'static {
    /// List all registrations, including soft-deleted entries.
    fn list(&self)
    -> LeaseResultFuture<'_, Vec<(String, StoredDocument<LeaseRegistrationRecord>)>>;

    /// Fetch one registration by key.
    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> LeaseResultFuture<'a, Option<StoredDocument<LeaseRegistrationRecord>>>;

    /// Return the current change-feed cursor for lease registrations.
    fn current_cursor(&self) -> LeaseResultFuture<'_, LeaseRegistrationCursor>;

    /// Return one ordered page of lease-registration changes after the supplied cursor.
    fn changes_since(
        &self,
        cursor: Option<LeaseRegistrationCursor>,
        limit: usize,
    ) -> LeaseResultFuture<'_, LeaseRegistrationChangePage>;

    /// Create a new registration. Fails when the key already exists.
    fn create<'a>(
        &'a self,
        key: &'a str,
        value: LeaseRegistrationRecord,
    ) -> LeaseResultFuture<'a, StoredDocument<LeaseRegistrationRecord>>;

    /// Create or update a registration with optimistic concurrency semantics.
    fn upsert<'a>(
        &'a self,
        key: &'a str,
        value: LeaseRegistrationRecord,
        expected_version: Option<u64>,
    ) -> LeaseResultFuture<'a, StoredDocument<LeaseRegistrationRecord>>;

    /// Soft-delete a registration with optional optimistic concurrency checking.
    fn soft_delete<'a>(
        &'a self,
        key: &'a str,
        expected_version: Option<u64>,
    ) -> LeaseResultFuture<'a, ()>;
}

impl LeaseRegistrationStore for DocumentStore<LeaseRegistrationRecord> {
    fn list(
        &self,
    ) -> LeaseResultFuture<'_, Vec<(String, StoredDocument<LeaseRegistrationRecord>)>> {
        Box::pin(async move { DocumentStore::list(self).await })
    }

    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> LeaseResultFuture<'a, Option<StoredDocument<LeaseRegistrationRecord>>> {
        Box::pin(async move { DocumentStore::get(self, key).await })
    }

    fn current_cursor(&self) -> LeaseResultFuture<'_, LeaseRegistrationCursor> {
        Box::pin(async move { DocumentStore::current_cursor(self).await })
    }

    fn changes_since(
        &self,
        cursor: Option<LeaseRegistrationCursor>,
        limit: usize,
    ) -> LeaseResultFuture<'_, LeaseRegistrationChangePage> {
        Box::pin(async move { DocumentStore::changes_since(self, cursor, limit).await })
    }

    fn create<'a>(
        &'a self,
        key: &'a str,
        value: LeaseRegistrationRecord,
    ) -> LeaseResultFuture<'a, StoredDocument<LeaseRegistrationRecord>> {
        Box::pin(async move { DocumentStore::create(self, key, value).await })
    }

    fn upsert<'a>(
        &'a self,
        key: &'a str,
        value: LeaseRegistrationRecord,
        expected_version: Option<u64>,
    ) -> LeaseResultFuture<'a, StoredDocument<LeaseRegistrationRecord>> {
        Box::pin(async move { DocumentStore::upsert(self, key, value, expected_version).await })
    }

    fn soft_delete<'a>(
        &'a self,
        key: &'a str,
        expected_version: Option<u64>,
    ) -> LeaseResultFuture<'a, ()> {
        Box::pin(async move { DocumentStore::soft_delete(self, key, expected_version).await })
    }
}

/// Cloneable handle to a lease-registration backend.
#[derive(Clone)]
pub struct LeaseRegistrationCollection {
    inner: Arc<dyn LeaseRegistrationStore>,
    local_store: Option<DocumentStore<LeaseRegistrationRecord>>,
}

impl LeaseRegistrationCollection {
    /// Wrap a lease-registration backend behind the shared boundary.
    pub fn from_backend(backend: impl LeaseRegistrationStore) -> Self {
        Self {
            inner: Arc::new(backend),
            local_store: None,
        }
    }

    /// Wrap one local file-backed document store behind the shared lease boundary.
    pub fn from_local_store(store: DocumentStore<LeaseRegistrationRecord>) -> Self {
        Self {
            inner: Arc::new(store.clone()),
            local_store: Some(store),
        }
    }

    /// Return the underlying local document store when this collection is file-backed.
    pub fn local_document_store(&self) -> Option<DocumentStore<LeaseRegistrationRecord>> {
        self.local_store.clone()
    }

    /// List all registrations, including soft-deleted entries.
    pub async fn list(&self) -> Result<Vec<(String, StoredDocument<LeaseRegistrationRecord>)>> {
        self.inner.list().await
    }

    /// Fetch one registration by key.
    pub async fn get(&self, key: &str) -> Result<Option<StoredDocument<LeaseRegistrationRecord>>> {
        self.inner.get(key).await
    }

    /// Return the current change-feed cursor for lease registrations.
    pub async fn current_cursor(&self) -> Result<LeaseRegistrationCursor> {
        self.inner.current_cursor().await
    }

    /// Return one ordered page of lease-registration changes after the supplied cursor.
    pub async fn changes_since(
        &self,
        cursor: Option<LeaseRegistrationCursor>,
        limit: usize,
    ) -> Result<LeaseRegistrationChangePage> {
        self.inner.changes_since(cursor, limit).await
    }

    /// Return one full snapshot checkpoint at the current collection revision.
    pub async fn snapshot_checkpoint(&self) -> Result<LeaseRegistrationSnapshotCheckpoint> {
        let Some(store) = &self.local_store else {
            return Err(PlatformError::unavailable(
                "lease snapshot checkpoints are not supported by this backend",
            ));
        };
        store.snapshot_checkpoint().await
    }

    /// Create a new registration. Fails when the key already exists.
    pub async fn create(
        &self,
        key: &str,
        value: LeaseRegistrationRecord,
    ) -> Result<StoredDocument<LeaseRegistrationRecord>> {
        self.inner.create(key, value).await
    }

    /// Create or update a registration with optimistic concurrency semantics.
    pub async fn upsert(
        &self,
        key: &str,
        value: LeaseRegistrationRecord,
        expected_version: Option<u64>,
    ) -> Result<StoredDocument<LeaseRegistrationRecord>> {
        self.inner.upsert(key, value, expected_version).await
    }

    /// Soft-delete a registration with optional optimistic concurrency checking.
    pub async fn soft_delete(&self, key: &str, expected_version: Option<u64>) -> Result<()> {
        self.inner.soft_delete(key, expected_version).await
    }

    /// Claim a fresh registration incarnation and rotate the fenced owner token.
    pub async fn claim_incarnation(
        &self,
        key: &str,
        mut value: LeaseRegistrationRecord,
    ) -> Result<StoredDocument<LeaseRegistrationRecord>> {
        let existing = self.get(key).await?;
        let expected_version = existing.as_ref().map(|stored| stored.version);
        let next_incarnation = next_lease_registration_incarnation(existing.as_ref())?;
        value.begin_new_incarnation_at(OffsetDateTime::now_utc(), next_incarnation);
        self.upsert(key, value, expected_version).await
    }

    /// Apply one registration mutation only when the caller still owns the current fence.
    pub async fn fenced_mutate<F>(
        &self,
        key: &str,
        fencing_token: &str,
        mut mutate: F,
    ) -> Result<Option<StoredDocument<LeaseRegistrationRecord>>>
    where
        F: FnMut(&mut LeaseRegistrationRecord),
    {
        if let Some(store) = &self.local_store {
            store.reload_from_disk().await?;
        }
        let Some(stored) = self.get(key).await? else {
            return Ok(None);
        };
        if stored.deleted {
            return Ok(None);
        }

        let original = stored.value;
        let mut record = original.clone();
        record.assert_fencing_token(fencing_token)?;
        mutate(&mut record);
        assert_fenced_registration_identity(key, &original, &record)?;
        Ok(Some(self.upsert(key, record, Some(stored.version)).await?))
    }

    /// Soft-delete every local registration whose lease has expired by the supplied time.
    pub async fn sweep_expired_at(&self, observed_at: OffsetDateTime) -> Result<usize> {
        let store = self.require_local_store()?;
        store
            .rewrite_collection(|collection| {
                let expired = collection
                    .records
                    .iter()
                    .filter_map(|(key, document)| {
                        (!document.deleted && document.value.lease_expires_at <= observed_at)
                            .then_some((key.clone(), document.version))
                    })
                    .collect::<Vec<_>>();
                let mut swept = 0_usize;
                for (key, version) in expired {
                    if let Some(document) = collection.records.get_mut(key.as_str()) {
                        document.value.set_drain_intent(LeaseDrainIntent::Draining);
                    }
                    DocumentStore::apply_soft_delete_to_collection(
                        collection,
                        key.as_str(),
                        Some(version),
                    )?;
                    swept = swept.saturating_add(1);
                }
                Ok((swept, swept > 0))
            })
            .await
    }

    /// Purge local soft-deleted registration tombstones older than the supplied cutoff.
    pub async fn sweep_tombstones_before(&self, cutoff: OffsetDateTime) -> Result<usize> {
        let store = self.require_local_store()?;
        store
            .rewrite_collection(|collection| {
                let initial_len = collection.records.len();
                collection
                    .records
                    .retain(|_, document| !(document.deleted && document.updated_at <= cutoff));
                let purged = initial_len.saturating_sub(collection.records.len());
                Ok((purged, purged > 0))
            })
            .await
    }

    /// Spawn the default local expiry and tombstone housekeeper for file-backed registrations.
    pub fn spawn_local_housekeeping(&self) -> Result<tokio::task::JoinHandle<()>> {
        self.spawn_local_housekeeping_with(
            default_local_lease_housekeeping_interval(),
            default_local_tombstone_retention(),
        )
    }

    /// Spawn a local expiry and tombstone housekeeper with explicit timing controls.
    pub fn spawn_local_housekeeping_with(
        &self,
        sweep_interval: StdDuration,
        tombstone_retention: Duration,
    ) -> Result<tokio::task::JoinHandle<()>> {
        if sweep_interval.is_zero() {
            return Err(PlatformError::invalid(
                "lease housekeeping sweep interval must be greater than zero",
            ));
        }
        if tombstone_retention < Duration::ZERO {
            return Err(PlatformError::invalid(
                "lease tombstone retention must be zero or positive",
            ));
        }

        let _ = self.require_local_store()?;
        let collection = self.clone();
        Ok(tokio::spawn(async move {
            let mut interval = tokio::time::interval(sweep_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                interval.tick().await;
                let observed_at = OffsetDateTime::now_utc();
                let _ = collection.sweep_expired_at(observed_at).await;
                let _ = collection
                    .sweep_tombstones_before(observed_at - tombstone_retention)
                    .await;
            }
        }))
    }

    /// Open the default file-backed lease-registration backend for all-in-one mode.
    pub async fn open_local(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::from_local_store(
            DocumentStore::<LeaseRegistrationRecord>::open(path).await?,
        ))
    }

    fn require_local_store(&self) -> Result<DocumentStore<LeaseRegistrationRecord>> {
        self.local_store.clone().ok_or_else(|| {
            PlatformError::invalid("lease sweeping requires a local document store backend")
        })
    }
}

impl fmt::Debug for LeaseRegistrationCollection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let backend = if self.local_store.is_some() {
            "local_document_store"
        } else {
            "dyn LeaseRegistrationStore"
        };
        formatter
            .debug_struct("LeaseRegistrationCollection")
            .field("backend", &backend)
            .finish()
    }
}

fn normalized_lease_duration_seconds(lease_duration_seconds: u32) -> u32 {
    lease_duration_seconds.max(1)
}

fn default_lease_registration_incarnation() -> u64 {
    1
}

fn normalized_lease_registration_incarnation(incarnation: u64) -> u64 {
    incarnation.max(default_lease_registration_incarnation())
}

fn lease_fencing_token(
    registration_id: &str,
    incarnation: u64,
    registered_at: OffsetDateTime,
) -> String {
    sha256_hex(
        format!(
            "lease-registration:v1:{registration_id}:{incarnation}:{}",
            registered_at.unix_timestamp_nanos()
        )
        .as_bytes(),
    )
}

fn next_lease_registration_incarnation(
    existing: Option<&StoredDocument<LeaseRegistrationRecord>>,
) -> Result<u64> {
    let Some(existing) = existing else {
        return Ok(default_lease_registration_incarnation());
    };
    normalized_lease_registration_incarnation(existing.value.incarnation)
        .checked_add(1)
        .ok_or_else(|| {
            PlatformError::conflict(format!(
                "lease registration `{}` incarnation overflowed",
                existing.value.registration_id
            ))
        })
}

fn assert_fenced_registration_identity(
    key: &str,
    original: &LeaseRegistrationRecord,
    mutated: &LeaseRegistrationRecord,
) -> Result<()> {
    if mutated.registration_id != original.registration_id || mutated.registration_id != key {
        return Err(PlatformError::conflict(
            "fenced lease mutation may not change registration_id",
        )
        .with_detail("claim a new registration incarnation to rotate ownership"));
    }
    if mutated.incarnation != original.incarnation {
        return Err(
            PlatformError::conflict("fenced lease mutation may not change incarnation")
                .with_detail("claim a new registration incarnation to rotate ownership"),
        );
    }
    if mutated.fencing_token != original.fencing_token {
        return Err(
            PlatformError::conflict("fenced lease mutation may not change fencing token")
                .with_detail("claim a new registration incarnation to rotate ownership"),
        );
    }
    if mutated.registered_at != original.registered_at {
        return Err(
            PlatformError::conflict("fenced lease mutation may not change registered_at")
                .with_detail("claim a new registration incarnation to rotate ownership"),
        );
    }
    Ok(())
}

fn lease_duration(lease_duration_seconds: u32) -> Duration {
    Duration::seconds(i64::from(normalized_lease_duration_seconds(
        lease_duration_seconds,
    )))
}

fn stale_window(lease_duration_seconds: u32) -> Duration {
    Duration::seconds(i64::from(
        (normalized_lease_duration_seconds(lease_duration_seconds) / 3).max(1),
    ))
}

fn default_local_lease_housekeeping_interval() -> StdDuration {
    StdDuration::from_secs(5)
}

fn default_local_tombstone_retention() -> Duration {
    Duration::seconds(60)
}

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;

    use time::{Duration, OffsetDateTime};

    use uhost_core::ErrorCode;
    use uhost_testkit::TempState;

    use super::{
        LeaseDrainIntent, LeaseFreshness, LeaseReadiness, LeaseRegistrationCollection,
        LeaseRegistrationRecord,
    };

    #[test]
    fn crate_root_reexports_lease_snapshot_checkpoint_alias() {
        let root_checkpoint: Option<crate::LeaseRegistrationSnapshotCheckpoint> = None;
        let _module_checkpoint: Option<super::LeaseRegistrationSnapshotCheckpoint> =
            root_checkpoint;
    }

    #[tokio::test]
    async fn local_lease_registration_collection_persists_readiness_and_drain_state() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let path = state
            .checked_join("registrations.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_a = LeaseRegistrationCollection::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_b = LeaseRegistrationCollection::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let created = collection_a
            .upsert(
                "all_in_one:node-a",
                LeaseRegistrationRecord::new(
                    "all_in_one:node-a",
                    "runtime_process",
                    "all_in_one:node-a",
                    "all_in_one",
                    Some(String::from("node-a")),
                    9,
                )
                .with_readiness(LeaseReadiness::Ready),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut updated_record = collection_b
            .get("all_in_one:node-a")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing durable registration"))
            .value;
        updated_record.set_drain_intent(LeaseDrainIntent::Draining);
        updated_record.renew();

        let updated = collection_b
            .upsert("all_in_one:node-a", updated_record, Some(created.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let loaded = collection_a
            .get("all_in_one:node-a")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing durable registration after update"));
        assert_eq!(loaded.version, updated.version);
        assert_eq!(loaded.value.readiness, LeaseReadiness::Ready);
        assert_eq!(loaded.value.drain_intent, LeaseDrainIntent::Draining);
        assert_eq!(
            loaded.value.lease_freshness_at(OffsetDateTime::now_utc()),
            LeaseFreshness::Fresh
        );
    }

    #[tokio::test]
    async fn local_lease_registration_collection_replays_changes_from_cursor() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let path = state
            .checked_join("registrations.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_a = LeaseRegistrationCollection::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_b = LeaseRegistrationCollection::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let origin = collection_a
            .current_cursor()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created = collection_a
            .upsert(
                "all_in_one:node-a",
                LeaseRegistrationRecord::new(
                    "all_in_one:node-a",
                    "runtime_process",
                    "all_in_one:node-a",
                    "all_in_one",
                    Some(String::from("node-a")),
                    9,
                )
                .with_readiness(LeaseReadiness::Ready),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first_page = collection_b
            .changes_since(Some(origin), 1)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first_page.changes.len(), 1);
        assert_eq!(first_page.changes[0].revision, 1);
        assert_eq!(first_page.changes[0].key, "all_in_one:node-a");
        assert_eq!(first_page.changes[0].document.version, 1);
        assert_eq!(
            first_page.changes[0].document.value.readiness,
            LeaseReadiness::Ready
        );
        assert_eq!(first_page.next_cursor.revision, 1);

        let mut updated = created.value.clone();
        updated.set_drain_intent(LeaseDrainIntent::Draining);
        updated.renew();
        let updated = collection_a
            .upsert("all_in_one:node-a", updated, Some(created.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        collection_a
            .soft_delete("all_in_one:node-a", Some(updated.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let second_page = collection_b
            .changes_since(Some(first_page.next_cursor), 10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second_page.changes.len(), 2);
        assert_eq!(second_page.changes[0].revision, 2);
        assert_eq!(second_page.changes[0].document.version, 2);
        assert_eq!(
            second_page.changes[0].document.value.drain_intent,
            LeaseDrainIntent::Draining
        );
        assert!(!second_page.changes[0].document.deleted);
        assert_eq!(second_page.changes[1].revision, 3);
        assert_eq!(second_page.changes[1].document.version, 3);
        assert!(second_page.changes[1].document.deleted);
        assert_eq!(second_page.next_cursor.revision, 3);

        let latest = collection_b
            .current_cursor()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(latest.revision, 3);
    }

    #[test]
    fn lease_freshness_detects_stale_and_expired_records() {
        let now = OffsetDateTime::now_utc();
        let mut record = LeaseRegistrationRecord::new(
            "all_in_one:node-a",
            "runtime_process",
            "all_in_one:node-a",
            "all_in_one",
            Some(String::from("node-a")),
            9,
        );

        record.lease_renewed_at = now - Duration::seconds(7);
        record.lease_expires_at = now + Duration::seconds(2);
        assert_eq!(record.lease_freshness_at(now), LeaseFreshness::Stale);

        record.lease_expires_at = now - Duration::seconds(1);
        assert_eq!(record.lease_freshness_at(now), LeaseFreshness::Expired);
    }

    #[tokio::test]
    async fn claim_incarnation_rotates_fencing_tokens_and_rejects_stale_mutation() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let path = state
            .checked_join("registrations.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let collection = LeaseRegistrationCollection::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first = collection
            .claim_incarnation(
                "all_in_one:node-a",
                LeaseRegistrationRecord::new(
                    "all_in_one:node-a",
                    "runtime_process",
                    "all_in_one:node-a",
                    "all_in_one",
                    Some(String::from("node-a")),
                    9,
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first.value.incarnation, 1);
        assert!(!first.value.fencing_token.is_empty());
        let first_token = first.value.fencing_token.clone();

        let second = collection
            .claim_incarnation(
                "all_in_one:node-a",
                LeaseRegistrationRecord::new(
                    "all_in_one:node-a",
                    "runtime_process",
                    "all_in_one:node-a",
                    "all_in_one",
                    Some(String::from("node-a")),
                    9,
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second.value.incarnation, 2);
        assert_ne!(second.value.fencing_token, first_token);

        let stale_error = collection
            .fenced_mutate("all_in_one:node-a", first_token.as_str(), |record| {
                record.renew();
            })
            .await
            .expect_err("stale fence should be rejected");
        assert_eq!(stale_error.code, ErrorCode::Conflict);

        let current = collection
            .fenced_mutate(
                "all_in_one:node-a",
                second.value.fencing_token.as_str(),
                |record| {
                    record.set_drain_intent(LeaseDrainIntent::Draining);
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing fenced registration"));
        assert_eq!(current.value.drain_intent, LeaseDrainIntent::Draining);
    }

    #[tokio::test]
    async fn fenced_mutate_rejects_identity_and_fence_tampering() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let path = state
            .checked_join("registrations.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let collection = LeaseRegistrationCollection::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let claimed = collection
            .claim_incarnation(
                "all_in_one:node-a",
                LeaseRegistrationRecord::new(
                    "all_in_one:node-a",
                    "runtime_process",
                    "all_in_one:node-a",
                    "all_in_one",
                    Some(String::from("node-a")),
                    9,
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let tamper_fence = collection
            .fenced_mutate(
                "all_in_one:node-a",
                claimed.value.fencing_token.as_str(),
                |record| {
                    record.fencing_token = String::from("forged");
                },
            )
            .await
            .expect_err("fence tampering should fail");
        assert_eq!(tamper_fence.code, ErrorCode::Conflict);

        let tamper_identity = collection
            .fenced_mutate(
                "all_in_one:node-a",
                claimed.value.fencing_token.as_str(),
                |record| {
                    record.registration_id = String::from("all_in_one:node-b");
                },
            )
            .await
            .expect_err("registration identity tampering should fail");
        assert_eq!(tamper_identity.code, ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn local_lease_registration_collection_sweeps_expired_records_and_purges_tombstones() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let path = state
            .checked_join("registrations.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let collection = LeaseRegistrationCollection::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let expired = collection
            .claim_incarnation(
                "all_in_one:expired-node",
                LeaseRegistrationRecord::new(
                    "all_in_one:expired-node",
                    "runtime_process",
                    "all_in_one:expired-node",
                    "all_in_one",
                    Some(String::from("node-a")),
                    9,
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        collection
            .fenced_mutate(
                "all_in_one:expired-node",
                expired.value.fencing_token.as_str(),
                |record| {
                    record.expire_now();
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        collection
            .claim_incarnation(
                "all_in_one:active-node",
                LeaseRegistrationRecord::new(
                    "all_in_one:active-node",
                    "runtime_process",
                    "all_in_one:active-node",
                    "all_in_one",
                    Some(String::from("node-b")),
                    9,
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let expired_swept = collection
            .sweep_expired_at(OffsetDateTime::now_utc())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(expired_swept, 1);

        let expired_document = collection
            .get("all_in_one:expired-node")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing expired registration"));
        assert!(expired_document.deleted);
        assert_eq!(
            expired_document.value.drain_intent,
            LeaseDrainIntent::Draining
        );

        let purged = collection
            .sweep_tombstones_before(OffsetDateTime::now_utc() + Duration::seconds(1))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(purged, 1);
        assert!(
            collection
                .get("all_in_one:expired-node")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );
        assert!(
            collection
                .get("all_in_one:active-node")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_some()
        );
    }

    #[tokio::test]
    async fn local_lease_registration_housekeeping_reaps_expired_tombstones() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let path = state
            .checked_join("registrations.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let collection = LeaseRegistrationCollection::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let claimed = collection
            .claim_incarnation(
                "all_in_one:node-a",
                LeaseRegistrationRecord::new(
                    "all_in_one:node-a",
                    "runtime_process",
                    "all_in_one:node-a",
                    "all_in_one",
                    Some(String::from("node-a")),
                    9,
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        collection
            .fenced_mutate(
                "all_in_one:node-a",
                claimed.value.fencing_token.as_str(),
                |record| {
                    record.expire_now();
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let housekeeping = collection
            .spawn_local_housekeeping_with(StdDuration::from_millis(20), Duration::ZERO)
            .unwrap_or_else(|error| panic!("{error}"));

        let mut purged = false;
        for _ in 0..20 {
            tokio::time::sleep(StdDuration::from_millis(20)).await;
            if collection
                .get("all_in_one:node-a")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
            {
                purged = true;
                break;
            }
        }

        housekeeping.abort();
        let _ = housekeeping.await;
        assert!(purged, "housekeeping did not purge the expired tombstone");
    }
}
