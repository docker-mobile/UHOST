//! File-backed document storage with optimistic concurrency.

use std::collections::{BTreeMap, HashMap};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Notify, RwLock};

use uhost_core::{PlatformError, Result, sha256_hex};

const MAX_RETAINED_DOCUMENT_CHANGES: usize = 256;

/// Stored document envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize", deserialize = "T: Deserialize<'de>"))]
pub struct StoredDocument<T> {
    /// Monotonic record version used for optimistic concurrency.
    pub version: u64,
    /// Timestamp of the last successful write.
    pub updated_at: OffsetDateTime,
    /// Soft-delete flag.
    pub deleted: bool,
    /// Domain value.
    pub value: T,
}

/// Stable cursor pointing to one collection change-feed revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct DocumentCursor {
    /// Monotonic collection revision consumed by one reader.
    #[serde(default)]
    pub revision: u64,
}

impl DocumentCursor {
    /// Return the origin cursor positioned before the first mutation.
    pub const fn origin() -> Self {
        Self { revision: 0 }
    }
}

/// Deterministic snapshot of one document mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize", deserialize = "T: Deserialize<'de>"))]
pub struct DocumentChange<T> {
    /// Monotonic collection revision assigned to this mutation.
    pub revision: u64,
    /// Stable record key mutated at this revision.
    pub key: String,
    /// Persisted document snapshot after the mutation completed.
    pub document: StoredDocument<T>,
}

/// One ordered page of deterministic document mutations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentChangePage<T> {
    /// Cursor that should be supplied on the next read.
    pub next_cursor: DocumentCursor,
    /// Changes ordered by ascending revision.
    pub changes: Vec<DocumentChange<T>>,
}

/// Point-in-time collection snapshot used to re-seed consumers after compaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentSnapshotCheckpoint<T> {
    /// Cursor positioned at the revision represented by this snapshot.
    pub cursor: DocumentCursor,
    /// Full document set at the checkpoint revision, including soft-deleted entries.
    pub records: BTreeMap<String, StoredDocument<T>>,
}

/// On-disk collection format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize", deserialize = "T: Deserialize<'de>"))]
pub struct DocumentCollection<T> {
    /// Collection schema version.
    pub schema_version: u16,
    /// Monotonic collection revision used by deterministic change-feed cursors.
    #[serde(default)]
    pub revision: u64,
    /// Highest revision compacted out of the retained change history.
    #[serde(default)]
    pub compacted_through_revision: u64,
    /// Records keyed by stable identifier.
    pub records: BTreeMap<String, StoredDocument<T>>,
    /// Ordered durable mutation history used to replay exact record changes.
    #[serde(default)]
    pub changes: Vec<DocumentChange<T>>,
}

impl<T> Default for DocumentCollection<T> {
    fn default() -> Self {
        Self {
            schema_version: 1,
            revision: 0,
            compacted_through_revision: 0,
            records: BTreeMap::new(),
            changes: Vec::new(),
        }
    }
}

/// Generic JSON document store.
#[derive(Debug)]
pub struct DocumentStore<T> {
    path: PathBuf,
    state: Arc<RwLock<DocumentCollection<T>>>,
    cache_state: Arc<RwLock<CollectionCacheState>>,
    shared_cache_state: Arc<RwLock<CollectionCacheState>>,
    write_guard: Arc<Mutex<()>>,
    change_notifier: Arc<Notify>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct CollectionCacheState {
    generation: u64,
    payload_sha256: String,
}

impl CollectionCacheState {
    fn from_payload(generation: u64, payload: &[u8]) -> Self {
        Self {
            generation,
            payload_sha256: sha256_hex(payload),
        }
    }
}

impl<T> Clone for DocumentStore<T> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            state: self.state.clone(),
            cache_state: self.cache_state.clone(),
            shared_cache_state: self.shared_cache_state.clone(),
            write_guard: self.write_guard.clone(),
            change_notifier: self.change_notifier.clone(),
        }
    }
}

impl<T> DocumentStore<T>
where
    T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
{
    /// Open or create a collection file.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(|error| {
                PlatformError::unavailable("failed to create document store directory")
                    .with_detail(error.to_string())
            })?;
            secure_directory_permissions(parent).await?;
        }

        if fs::metadata(&path).await.is_err() {
            Self::write_collection(&path, &DocumentCollection::<T>::default()).await?;
        }
        let path = fs::canonicalize(&path).await.map_err(|error| {
            PlatformError::unavailable("failed to canonicalize document store path")
                .with_detail(error.to_string())
        })?;
        if let Some(parent) = path.parent() {
            secure_directory_permissions(parent).await?;
        }
        secure_file_permissions(&path).await?;
        let write_guard = shared_write_guard(&path);
        let change_notifier = shared_change_notifier(&path);
        let (collection, cache_state, shared_cache_state) = {
            let _guard = write_guard.lock().await;
            let (collection, needs_write_back) = Self::read_collection_with_status(&path).await?;
            if needs_write_back {
                Self::write_collection(&path, &collection).await?;
            }
            let cache_state = Self::cache_state_for_collection(&collection)?;
            let shared_cache_state = shared_collection_cache_state(&path, &cache_state);
            let shared_changed = {
                let shared = shared_cache_state.read().await.clone();
                shared != cache_state
            };
            if shared_changed {
                *shared_cache_state.write().await = cache_state.clone();
                change_notifier.notify_waiters();
            }
            (collection, cache_state, shared_cache_state)
        };

        Ok(Self {
            path,
            state: Arc::new(RwLock::new(collection)),
            cache_state: Arc::new(RwLock::new(cache_state)),
            shared_cache_state,
            write_guard,
            change_notifier,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) async fn snapshot_collection(&self) -> Result<DocumentCollection<T>> {
        self.refresh_from_disk_if_changed().await?;
        Ok(self.state.read().await.clone())
    }

    /// Reload the collection from disk even when the shared cache state has not changed.
    pub async fn reload_from_disk(&self) -> Result<()> {
        loop {
            let observed = self.shared_cache_state.read().await.clone();
            if self
                .refresh_from_disk_against_shared_state(observed)
                .await?
            {
                return Ok(());
            }
        }
    }

    pub(crate) async fn install_committed_collection(
        &self,
        collection: DocumentCollection<T>,
    ) -> Result<()> {
        let cache_state = Self::cache_state_for_collection(&collection)?;
        self.install_cached_collection(collection, cache_state, true)
            .await;
        Ok(())
    }

    /// List all records including soft-deleted entries.
    pub async fn list(&self) -> Result<Vec<(String, StoredDocument<T>)>> {
        self.refresh_from_disk_if_changed().await?;
        Ok(self
            .state
            .read()
            .await
            .records
            .iter()
            .map(|(key, document)| (key.clone(), document.clone()))
            .collect())
    }

    /// Fetch a record by key.
    pub async fn get(&self, key: &str) -> Result<Option<StoredDocument<T>>> {
        self.refresh_from_disk_if_changed().await?;
        Ok(self.state.read().await.records.get(key).cloned())
    }

    /// Return the current deterministic change-feed cursor for this collection.
    pub async fn current_cursor(&self) -> Result<DocumentCursor> {
        self.refresh_from_disk_if_changed().await?;
        Ok(DocumentCursor {
            revision: self.state.read().await.revision,
        })
    }

    /// Return a full snapshot checkpoint at the current collection revision.
    pub async fn snapshot_checkpoint(&self) -> Result<DocumentSnapshotCheckpoint<T>> {
        self.refresh_from_disk_if_changed().await?;
        let state = self.state.read().await;
        Ok(DocumentSnapshotCheckpoint {
            cursor: DocumentCursor {
                revision: state.revision,
            },
            records: state.records.clone(),
        })
    }

    /// Return one ordered page of changes strictly after the supplied cursor.
    pub async fn changes_since(
        &self,
        cursor: Option<DocumentCursor>,
        limit: usize,
    ) -> Result<DocumentChangePage<T>> {
        if limit == 0 {
            return Err(PlatformError::invalid(
                "document change-feed limit must be greater than zero",
            ));
        }

        self.refresh_from_disk_if_changed().await?;
        let state = self.state.read().await;
        let cursor = cursor.unwrap_or_else(DocumentCursor::origin);
        if cursor.revision > state.revision {
            return Err(PlatformError::conflict(format!(
                "document cursor revision {} is ahead of collection revision {}",
                cursor.revision, state.revision
            )));
        }
        if cursor.revision < state.compacted_through_revision {
            return Err(PlatformError::conflict(format!(
                "document cursor revision {} has been compacted; reload from snapshot checkpoint at revision {}",
                cursor.revision, state.revision
            )));
        }

        let changes = state
            .changes
            .iter()
            .filter(|change| change.revision > cursor.revision)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let next_cursor = changes.last().map_or(
            DocumentCursor {
                revision: state.revision,
            },
            |change| DocumentCursor {
                revision: change.revision,
            },
        );
        Ok(DocumentChangePage {
            next_cursor,
            changes,
        })
    }

    /// Insert a new record. Fails if the key already exists.
    pub async fn create(&self, key: &str, value: T) -> Result<StoredDocument<T>> {
        let _guard = self.write_guard.lock().await;
        self.refresh_from_disk_if_changed().await?;
        let mut next_collection = self.state.read().await.clone();
        let document = Self::apply_create_to_collection(&mut next_collection, key, value)?;
        let cache_state = Self::write_collection(&self.path, &next_collection).await?;
        self.install_cached_collection(next_collection, cache_state, true)
            .await;
        Ok(document)
    }

    /// Create or update a record with optional optimistic concurrency.
    pub async fn upsert(
        &self,
        key: &str,
        value: T,
        expected_version: Option<u64>,
    ) -> Result<StoredDocument<T>> {
        let _guard = self.write_guard.lock().await;
        self.refresh_from_disk_if_changed().await?;
        let mut next_collection = self.state.read().await.clone();
        let document =
            Self::apply_upsert_to_collection(&mut next_collection, key, value, expected_version)?;
        let cache_state = Self::write_collection(&self.path, &next_collection).await?;
        self.install_cached_collection(next_collection, cache_state, true)
            .await;
        Ok(document)
    }

    /// Soft-delete a record.
    pub async fn soft_delete(&self, key: &str, expected_version: Option<u64>) -> Result<()> {
        let _guard = self.write_guard.lock().await;
        self.refresh_from_disk_if_changed().await?;
        let mut next_collection = self.state.read().await.clone();
        Self::apply_soft_delete_to_collection(&mut next_collection, key, expected_version)?;
        let cache_state = Self::write_collection(&self.path, &next_collection).await?;
        self.install_cached_collection(next_collection, cache_state, true)
            .await;
        Ok(())
    }

    pub(crate) async fn wait_for_revision_advance(
        &self,
        cursor: DocumentCursor,
        poll_interval: Duration,
        timeout: Duration,
    ) -> Result<DocumentCursor> {
        let poll_interval = if poll_interval.is_zero() {
            Duration::from_millis(25)
        } else {
            poll_interval
        };
        let started_at = Instant::now();

        loop {
            let notified = self.change_notifier.notified();
            let current = self.current_cursor().await?;
            let elapsed = started_at.elapsed();
            if current.revision > cursor.revision || elapsed >= timeout {
                return Ok(current);
            }

            let remaining = timeout.saturating_sub(elapsed);
            let wait_for = remaining.min(poll_interval);
            if wait_for.is_zero() {
                return Ok(current);
            }

            let _ = tokio::time::timeout(wait_for, notified).await;
        }
    }

    /// Apply one in-memory collection rewrite and durably commit it when mutated.
    pub(crate) async fn rewrite_collection<R, F>(&self, mut rewrite: F) -> Result<R>
    where
        F: FnMut(&mut DocumentCollection<T>) -> Result<(R, bool)>,
    {
        let _guard = self.write_guard.lock().await;
        self.refresh_from_disk_if_changed().await?;
        let mut next_collection = self.state.read().await.clone();
        let (result, changed) = rewrite(&mut next_collection)?;
        if !changed {
            return Ok(result);
        }

        let cache_state = Self::write_collection(&self.path, &next_collection).await?;
        self.install_cached_collection(next_collection, cache_state, true)
            .await;
        Ok(result)
    }

    pub(crate) async fn refresh_from_disk_if_changed(&self) -> Result<()> {
        loop {
            let observed = self.shared_cache_state.read().await.clone();
            let cached = self.cache_state.read().await.clone();
            if observed == cached {
                return Ok(());
            }
            if self
                .refresh_from_disk_against_shared_state(observed)
                .await?
            {
                return Ok(());
            }
        }
    }

    async fn read_collection_with_status(path: &Path) -> Result<(DocumentCollection<T>, bool)> {
        let raw = fs::read(path).await.map_err(|error| {
            PlatformError::unavailable("failed to read document collection")
                .with_detail(format!("{} ({error})", path.display()))
        })?;
        let collection = serde_json::from_slice(&raw).map_err(|error| {
            PlatformError::unavailable("failed to decode document collection")
                .with_detail(format!("{} ({error})", path.display()))
        })?;
        let normalized = Self::normalize_collection(collection)?;
        let normalized_payload = Self::encode_collection_payload(&normalized)?;
        Ok((normalized, normalized_payload != raw))
    }

    async fn read_collection(path: &Path) -> Result<DocumentCollection<T>> {
        Ok(Self::read_collection_with_status(path).await?.0)
    }

    async fn install_cached_collection(
        &self,
        collection: DocumentCollection<T>,
        cache_state: CollectionCacheState,
        notify_watchers: bool,
    ) {
        *self.state.write().await = collection;
        *self.cache_state.write().await = cache_state.clone();
        *self.shared_cache_state.write().await = cache_state;
        if notify_watchers {
            self.change_notifier.notify_waiters();
        }
    }

    async fn install_local_collection(
        &self,
        collection: DocumentCollection<T>,
        cache_state: CollectionCacheState,
    ) {
        *self.state.write().await = collection;
        *self.cache_state.write().await = cache_state;
    }

    async fn refresh_from_disk_against_shared_state(
        &self,
        observed: CollectionCacheState,
    ) -> Result<bool> {
        // Multiple handles can point at the same collection path. `Ok(false)`
        // means another handle published a newer shared-cache fingerprint first,
        // so the caller should retry instead of overwriting that newer state
        // with the stale fingerprint it observed before re-reading the file.
        let latest = Self::read_collection(&self.path).await?;
        let latest_cache_state = Self::cache_state_for_collection(&latest)?;

        let (installed_cache_state, notify_watchers) = {
            let mut shared = self.shared_cache_state.write().await;
            if *shared != observed {
                // Another handle already republished a newer fingerprint; retry instead of
                // overwriting the shared cache state with a stale read.
                if *shared != latest_cache_state {
                    return Ok(false);
                }
                (shared.clone(), false)
            } else {
                let notify_watchers = *shared != latest_cache_state;
                *shared = latest_cache_state.clone();
                (latest_cache_state.clone(), notify_watchers)
            }
        };

        self.install_local_collection(latest, installed_cache_state)
            .await;
        if notify_watchers {
            self.change_notifier.notify_waiters();
        }
        Ok(true)
    }

    fn cache_state_for_collection(
        collection: &DocumentCollection<T>,
    ) -> Result<CollectionCacheState> {
        let payload = Self::encode_collection_payload(collection)?;
        Ok(CollectionCacheState::from_payload(
            collection.revision,
            &payload,
        ))
    }

    async fn write_collection(
        path: &Path,
        collection: &DocumentCollection<T>,
    ) -> Result<CollectionCacheState> {
        let temp_path = unique_temp_path(path);
        let payload = Self::encode_collection_payload(collection)?;
        let cache_state = CollectionCacheState::from_payload(collection.revision, &payload);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).truncate(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut temp = options.open(&temp_path).await.map_err(|error| {
            PlatformError::unavailable("failed to open collection temp file")
                .with_detail(error.to_string())
        })?;
        temp.write_all(&payload).await.map_err(|error| {
            PlatformError::unavailable("failed to write collection temp file")
                .with_detail(error.to_string())
        })?;
        temp.flush().await.map_err(|error| {
            PlatformError::unavailable("failed to flush collection temp file")
                .with_detail(error.to_string())
        })?;
        temp.sync_all().await.map_err(|error| {
            PlatformError::unavailable("failed to sync collection temp file")
                .with_detail(error.to_string())
        })?;
        drop(temp);

        if let Err(error) = fs::rename(&temp_path, path).await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(
                PlatformError::unavailable("failed to commit collection update")
                    .with_detail(error.to_string()),
            );
        }
        secure_file_permissions(path).await?;
        sync_parent_dir(path).await?;
        Ok(cache_state)
    }

    pub(crate) fn encode_collection_payload(collection: &DocumentCollection<T>) -> Result<Vec<u8>> {
        serde_json::to_vec(collection).map_err(|error| {
            PlatformError::unavailable("failed to encode document collection")
                .with_detail(error.to_string())
        })
    }

    pub(crate) fn apply_create_to_collection(
        collection: &mut DocumentCollection<T>,
        key: &str,
        value: T,
    ) -> Result<StoredDocument<T>> {
        if collection.records.contains_key(key) {
            return Err(PlatformError::conflict(format!(
                "record `{key}` already exists"
            )));
        }

        let document = StoredDocument {
            version: 1,
            updated_at: OffsetDateTime::now_utc(),
            deleted: false,
            value,
        };
        collection.records.insert(key.to_owned(), document.clone());
        Self::append_change(collection, key, &document)?;
        Ok(document)
    }

    pub(crate) fn apply_upsert_to_collection(
        collection: &mut DocumentCollection<T>,
        key: &str,
        value: T,
        expected_version: Option<u64>,
    ) -> Result<StoredDocument<T>> {
        let version = match collection.records.get(key) {
            Some(existing) => {
                if let Some(expected) = expected_version
                    && existing.version != expected
                {
                    return Err(PlatformError::conflict(format!(
                        "version mismatch for `{key}`"
                    )));
                }
                existing.version.checked_add(1).ok_or_else(|| {
                    PlatformError::conflict(format!("record `{key}` version overflowed"))
                })?
            }
            None => {
                if expected_version.is_some() {
                    return Err(PlatformError::not_found(format!(
                        "record `{key}` does not exist"
                    )));
                }
                1
            }
        };

        let document = StoredDocument {
            version,
            updated_at: OffsetDateTime::now_utc(),
            deleted: false,
            value,
        };
        collection.records.insert(key.to_owned(), document.clone());
        Self::append_change(collection, key, &document)?;
        Ok(document)
    }

    pub(crate) fn apply_soft_delete_to_collection(
        collection: &mut DocumentCollection<T>,
        key: &str,
        expected_version: Option<u64>,
    ) -> Result<StoredDocument<T>> {
        let document = {
            let Some(document) = collection.records.get_mut(key) else {
                return Err(PlatformError::not_found(format!(
                    "record `{key}` does not exist"
                )));
            };

            if let Some(expected) = expected_version
                && document.version != expected
            {
                return Err(PlatformError::conflict(format!(
                    "version mismatch for `{key}`"
                )));
            }

            document.version = document.version.checked_add(1).ok_or_else(|| {
                PlatformError::conflict(format!("record `{key}` version overflowed"))
            })?;
            document.updated_at = OffsetDateTime::now_utc();
            document.deleted = true;
            document.clone()
        };
        Self::append_change(collection, key, &document)?;
        Ok(document)
    }

    fn append_change(
        collection: &mut DocumentCollection<T>,
        key: &str,
        document: &StoredDocument<T>,
    ) -> Result<()> {
        let revision = collection.revision.checked_add(1).ok_or_else(|| {
            PlatformError::conflict(format!(
                "document collection revision overflowed while writing `{key}`"
            ))
        })?;
        collection.revision = revision;
        collection.changes.push(DocumentChange {
            revision,
            key: key.to_owned(),
            document: document.clone(),
        });
        Self::compact_change_log(collection);
        Ok(())
    }

    fn compact_change_log(collection: &mut DocumentCollection<T>) {
        if collection.changes.len() <= MAX_RETAINED_DOCUMENT_CHANGES {
            return;
        }

        let compacted = collection.changes.len() - MAX_RETAINED_DOCUMENT_CHANGES;
        let compacted_through_revision = collection
            .changes
            .get(compacted.saturating_sub(1))
            .map(|change| change.revision)
            .unwrap_or(collection.compacted_through_revision);
        collection.changes.drain(..compacted);
        collection.compacted_through_revision = collection
            .compacted_through_revision
            .max(compacted_through_revision);
    }

    fn normalize_collection(
        mut collection: DocumentCollection<T>,
    ) -> Result<DocumentCollection<T>> {
        // Normalization repairs three shapes: legacy collections with no change
        // log, partially compacted histories whose revisions need to be
        // re-trimmed, and current collections that only need revision/retention
        // reconciliation after sorting the persisted change feed.
        if collection.changes.is_empty() {
            if collection.revision > 0 || collection.compacted_through_revision > 0 {
                collection.revision = collection
                    .revision
                    .max(collection.compacted_through_revision);
                return Ok(collection);
            }
            let mut revision = 0_u64;
            let mut changes = Vec::with_capacity(collection.records.len());
            for (key, document) in &collection.records {
                revision = revision.checked_add(1).ok_or_else(|| {
                    PlatformError::conflict(
                        "document collection revision overflowed while rebuilding change history",
                    )
                })?;
                changes.push(DocumentChange {
                    revision,
                    key: key.clone(),
                    document: document.clone(),
                });
            }
            collection.revision = revision;
            collection.changes = changes;
            return Ok(collection);
        }

        collection.changes.sort_by_key(|change| change.revision);
        collection
            .changes
            .retain(|change| change.revision > collection.compacted_through_revision);
        collection.revision = collection
            .revision
            .max(collection.compacted_through_revision)
            .max(
                collection
                    .changes
                    .last()
                    .map(|change| change.revision)
                    .unwrap_or_default(),
            );
        Self::compact_change_log(&mut collection);
        collection.revision = collection
            .changes
            .last()
            .map(|change| change.revision)
            .unwrap_or(collection.revision);
        Ok(collection)
    }
}

pub(crate) async fn secure_directory_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|error| {
                PlatformError::unavailable("failed to harden document store directory permissions")
                    .with_detail(error.to_string())
            })?;
    }
    Ok(())
}

pub(crate) async fn secure_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|error| {
                PlatformError::unavailable("failed to harden document store file permissions")
                    .with_detail(error.to_string())
            })?;
    }
    Ok(())
}

pub(crate) async fn sync_parent_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            let dir = fs::File::open(parent).await.map_err(|error| {
                PlatformError::unavailable("failed to open document store directory for sync")
                    .with_detail(error.to_string())
            })?;
            dir.sync_all().await.map_err(|error| {
                PlatformError::unavailable("failed to sync document store directory")
                    .with_detail(error.to_string())
            })?;
        }
    }
    Ok(())
}

pub(crate) fn shared_write_guard(path: &Path) -> Arc<Mutex<()>> {
    static REGISTRY: OnceLock<StdMutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();

    let registry = REGISTRY.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut registry = registry.lock().unwrap_or_else(|poison| poison.into_inner());
    registry
        .entry(path.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

pub(crate) fn shared_change_notifier(path: &Path) -> Arc<Notify> {
    static REGISTRY: OnceLock<StdMutex<HashMap<PathBuf, Arc<Notify>>>> = OnceLock::new();

    let registry = REGISTRY.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut registry = registry.lock().unwrap_or_else(|poison| poison.into_inner());
    registry
        .entry(path.to_path_buf())
        .or_insert_with(|| Arc::new(Notify::new()))
        .clone()
}

fn shared_collection_cache_state(
    path: &Path,
    initial: &CollectionCacheState,
) -> Arc<RwLock<CollectionCacheState>> {
    static REGISTRY: OnceLock<StdMutex<HashMap<PathBuf, Arc<RwLock<CollectionCacheState>>>>> =
        OnceLock::new();

    let registry = REGISTRY.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut registry = registry.lock().unwrap_or_else(|poison| poison.into_inner());
    registry
        .entry(path.to_path_buf())
        .or_insert_with(|| Arc::new(RwLock::new(initial.clone())))
        .clone()
}

pub(crate) fn unique_temp_path(path: &Path) -> PathBuf {
    static COUNTER: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();

    let counter = COUNTER.get_or_init(|| std::sync::atomic::AtomicU64::new(0));
    let suffix = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut temp_path = path.to_path_buf();
    let extension = format!("{}.{}.tmp", std::process::id(), suffix);
    temp_path.set_extension(extension);
    temp_path
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};
    use tempfile::tempdir;
    use time::OffsetDateTime;
    use tokio::fs;

    use uhost_core::ErrorCode;

    use super::{
        CollectionCacheState, DocumentChange, DocumentCollection, DocumentCursor, DocumentStore,
        MAX_RETAINED_DOCUMENT_CHANGES, StoredDocument,
    };

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Example {
        name: String,
    }

    fn stored_example(name: &str) -> StoredDocument<Example> {
        StoredDocument {
            version: 1,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            deleted: false,
            value: Example {
                name: String::from(name),
            },
        }
    }

    fn single_record_collection(name: &str) -> DocumentCollection<Example> {
        let document = stored_example(name);
        DocumentCollection {
            schema_version: 1,
            revision: 1,
            compacted_through_revision: 0,
            records: BTreeMap::from([(String::from("alpha"), document.clone())]),
            changes: vec![DocumentChange {
                revision: 1,
                key: String::from("alpha"),
                document,
            }],
        }
    }

    #[test]
    fn cache_state_checksum_distinguishes_same_generation_same_length_payloads() {
        let first = DocumentCollection {
            schema_version: 1,
            revision: 7,
            compacted_through_revision: 0,
            records: BTreeMap::from([(String::from("alpha"), stored_example("one"))]),
            changes: Vec::new(),
        };
        let second = DocumentCollection {
            schema_version: 1,
            revision: 7,
            compacted_through_revision: 0,
            records: BTreeMap::from([(String::from("alpha"), stored_example("two"))]),
            changes: Vec::new(),
        };

        let first_payload = DocumentStore::<Example>::encode_collection_payload(&first)
            .unwrap_or_else(|error| panic!("{error}"));
        let second_payload = DocumentStore::<Example>::encode_collection_payload(&second)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(first_payload.len(), second_payload.len());

        let first_state = CollectionCacheState::from_payload(first.revision, &first_payload);
        let second_state = CollectionCacheState::from_payload(second.revision, &second_payload);

        assert_eq!(first_state.generation, second_state.generation);
        assert_ne!(first_state.payload_sha256, second_state.payload_sha256);
    }

    #[tokio::test]
    async fn create_and_read_document() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = DocumentStore::<Example>::open(temp.path().join("docs.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        store
            .create(
                "alpha",
                Example {
                    name: String::from("primary"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let loaded = store
            .get("alpha")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing document"));
        assert_eq!(loaded.value.name, "primary");
    }

    #[tokio::test]
    async fn concurrent_writes_from_independent_handles_are_serialized() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("docs.json");
        let store_a = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let store_b = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first = store_a.create(
            "alpha",
            Example {
                name: String::from("one"),
            },
        );
        let second = store_b.create(
            "bravo",
            Example {
                name: String::from("two"),
            },
        );

        let (first, second) = tokio::join!(first, second);
        first.unwrap_or_else(|error| panic!("{error}"));
        second.unwrap_or_else(|error| panic!("{error}"));

        let loaded = store_a
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(loaded.len(), 2);
        assert!(loaded.iter().any(|(key, _)| key == "alpha"));
        assert!(loaded.iter().any(|(key, _)| key == "bravo"));
    }

    #[tokio::test]
    async fn cache_busts_refresh_independent_handles_from_shared_cache_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("docs.json");
        let store_a = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let store_b = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let initial_local = store_b.cache_state.read().await.clone();
        store_a
            .create(
                "alpha",
                Example {
                    name: String::from("one"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stale_local = store_b.cache_state.read().await.clone();
        let shared = store_b.shared_cache_state.read().await.clone();
        assert_eq!(stale_local, initial_local);
        assert_ne!(shared, stale_local);

        let loaded = store_b
            .get("alpha")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing document"));
        assert_eq!(loaded.value.name, "one");

        let refreshed_local = store_b.cache_state.read().await.clone();
        assert_eq!(refreshed_local, shared);
    }

    #[tokio::test]
    async fn install_committed_collection_updates_shared_cache_state_for_other_handles() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("docs.json");
        let store_a = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let store_b = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut next_collection = store_a
            .snapshot_collection()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        DocumentStore::apply_create_to_collection(
            &mut next_collection,
            "alpha",
            Example {
                name: String::from("journal"),
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let expected_cache_state = DocumentStore::write_collection(&path, &next_collection)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        store_a
            .install_committed_collection(next_collection)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let shared = store_b.shared_cache_state.read().await.clone();
        assert_eq!(shared, expected_cache_state);

        let loaded = store_b
            .get("alpha")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing document"));
        assert_eq!(loaded.value.name, "journal");
    }

    #[tokio::test]
    async fn opening_new_handle_republishes_out_of_band_rewrites() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("docs.json");
        let store_a = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        store_a
            .create(
                "alpha",
                Example {
                    name: String::from("safe"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut next_collection = store_a
            .snapshot_collection()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let updated = next_collection
            .records
            .get_mut("alpha")
            .unwrap_or_else(|| panic!("missing alpha record"));
        updated.value.name = String::from("external");
        updated.version = 2;
        updated.updated_at = OffsetDateTime::now_utc();
        DocumentStore::write_collection(&path, &next_collection)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stale = store_a
            .get("alpha")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing alpha record"));
        assert_eq!(stale.value.name, "safe");

        let _store_b = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let refreshed = store_a
            .get("alpha")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing alpha record"));
        assert_eq!(refreshed.value.name, "external");
    }

    #[tokio::test]
    async fn opening_new_handle_republishes_same_generation_same_length_rewrites() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("docs.json");
        let initial = single_record_collection("one");
        let rewritten = single_record_collection("two");

        let initial_payload = DocumentStore::<Example>::encode_collection_payload(&initial)
            .unwrap_or_else(|error| panic!("{error}"));
        let rewritten_payload = DocumentStore::<Example>::encode_collection_payload(&rewritten)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(initial.revision, rewritten.revision);
        assert_eq!(initial_payload.len(), rewritten_payload.len());

        DocumentStore::<Example>::write_collection(&path, &initial)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let store_a = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        DocumentStore::<Example>::write_collection(&path, &rewritten)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stale = store_a
            .get("alpha")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing alpha record"));
        assert_eq!(stale.value.name, "one");

        let _store_b = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let refreshed = store_a
            .get("alpha")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing alpha record"));
        assert_eq!(refreshed.value.name, "two");
    }

    #[tokio::test]
    async fn reload_from_disk_detects_external_collection_corruption() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("docs.json");
        let store = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        store
            .create(
                "alpha",
                Example {
                    name: String::from("safe"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        fs::write(&path, b"{broken-json")
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = store
            .reload_from_disk()
            .await
            .expect_err("external corruption should fail explicit reload");
        assert!(
            error
                .to_string()
                .contains("failed to decode document collection"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn wait_for_revision_advance_wakes_on_cross_handle_writes() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("docs.json");
        let store_a = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let store_b = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let cursor = store_a
            .current_cursor()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let started_at = Instant::now();
        let waiter = tokio::spawn({
            let store = store_a.clone();
            async move {
                store
                    .wait_for_revision_advance(
                        cursor,
                        Duration::from_secs(10),
                        Duration::from_secs(1),
                    )
                    .await
                    .unwrap_or_else(|error| panic!("{error}"))
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        store_b
            .create(
                "alpha",
                Example {
                    name: String::from("one"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let advanced = waiter.await.unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(advanced.revision, 1);
        assert!(started_at.elapsed() < Duration::from_millis(900));
    }

    #[tokio::test]
    async fn change_feed_tracks_deterministic_document_mutations() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = DocumentStore::<Example>::open(temp.path().join("docs.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let origin = store
            .current_cursor()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(origin, DocumentCursor::origin());

        let created = store
            .create(
                "alpha",
                Example {
                    name: String::from("one"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_page = store
            .changes_since(Some(origin), 1)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first_page.changes.len(), 1);
        assert_eq!(first_page.changes[0].revision, 1);
        assert_eq!(first_page.changes[0].key, "alpha");
        assert_eq!(first_page.changes[0].document.version, 1);
        assert!(!first_page.changes[0].document.deleted);
        assert_eq!(first_page.changes[0].document.value.name, "one");
        assert_eq!(first_page.next_cursor.revision, 1);

        let updated = store
            .upsert(
                "alpha",
                Example {
                    name: String::from("two"),
                },
                Some(created.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        store
            .soft_delete("alpha", Some(updated.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let second_page = store
            .changes_since(Some(first_page.next_cursor), 10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second_page.changes.len(), 2);
        assert_eq!(second_page.changes[0].revision, 2);
        assert_eq!(second_page.changes[0].document.version, 2);
        assert_eq!(second_page.changes[0].document.value.name, "two");
        assert!(!second_page.changes[0].document.deleted);
        assert_eq!(second_page.changes[1].revision, 3);
        assert_eq!(second_page.changes[1].document.version, 3);
        assert!(second_page.changes[1].document.deleted);
        assert_eq!(second_page.next_cursor.revision, 3);

        let latest = store
            .current_cursor()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(latest.revision, 3);
        let empty_page = store
            .changes_since(Some(latest), 10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(empty_page.changes.is_empty());
        assert_eq!(empty_page.next_cursor, latest);
    }

    #[tokio::test]
    async fn change_feed_bootstraps_legacy_collections_without_revision_metadata() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("docs.json");
        let now = OffsetDateTime::now_utc();
        let legacy = serde_json::json!({
            "schema_version": 1,
            "records": {
                "bravo": {
                    "version": 1,
                    "updated_at": now,
                    "deleted": false,
                    "value": {"name": "two"}
                },
                "alpha": {
                    "version": 2,
                    "updated_at": now,
                    "deleted": true,
                    "value": {"name": "one"}
                }
            }
        });
        fs::write(
            &path,
            serde_json::to_vec(&legacy).unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let store = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let page = store
            .changes_since(None, 10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(page.changes.len(), 2);
        assert_eq!(page.changes[0].revision, 1);
        assert_eq!(page.changes[0].key, "alpha");
        assert_eq!(page.changes[0].document.version, 2);
        assert!(page.changes[0].document.deleted);
        assert_eq!(page.changes[1].revision, 2);
        assert_eq!(page.changes[1].key, "bravo");
        assert_eq!(page.changes[1].document.value.name, "two");
        assert_eq!(page.next_cursor.revision, 2);
    }

    #[tokio::test]
    async fn change_feed_rejects_future_cursors() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = DocumentStore::<Example>::open(temp.path().join("docs.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        store
            .create(
                "alpha",
                Example {
                    name: String::from("one"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = store
            .changes_since(Some(DocumentCursor { revision: 2 }), 10)
            .await
            .expect_err("future cursor should fail");
        assert_eq!(error.code, ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn change_feed_compacts_old_history_and_serves_snapshot_checkpoints() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("docs.json");
        let store = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let total_writes = MAX_RETAINED_DOCUMENT_CHANGES + 5;
        for index in 0..total_writes {
            let key = format!("doc-{index}");
            store
                .create(
                    key.as_str(),
                    Example {
                        name: format!("name-{index}"),
                    },
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let collection = store
            .snapshot_collection()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(collection.revision, total_writes as u64);
        assert_eq!(collection.compacted_through_revision, 5);
        assert_eq!(collection.changes.len(), MAX_RETAINED_DOCUMENT_CHANGES);
        assert_eq!(
            collection.changes[0].revision,
            collection.compacted_through_revision + 1
        );

        let checkpoint = store
            .snapshot_checkpoint()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(checkpoint.cursor.revision, total_writes as u64);
        assert_eq!(checkpoint.records.len(), total_writes);
        assert_eq!(
            checkpoint
                .records
                .get("doc-0")
                .unwrap_or_else(|| panic!("missing checkpointed record"))
                .value
                .name,
            "name-0"
        );

        let stale_error = store
            .changes_since(Some(DocumentCursor::origin()), 10)
            .await
            .expect_err("stale cursor should fail after compaction");
        assert_eq!(stale_error.code, ErrorCode::Conflict);

        let replay_page = store
            .changes_since(
                Some(DocumentCursor {
                    revision: collection.compacted_through_revision,
                }),
                MAX_RETAINED_DOCUMENT_CHANGES,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(replay_page.changes.len(), MAX_RETAINED_DOCUMENT_CHANGES);
        assert_eq!(
            replay_page.changes[0].revision,
            collection.compacted_through_revision + 1
        );
        assert_eq!(replay_page.next_cursor.revision, total_writes as u64);

        let reopened = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let reopened_collection = reopened
            .snapshot_collection()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            reopened_collection.compacted_through_revision,
            collection.compacted_through_revision
        );
        assert_eq!(
            reopened_collection.changes.len(),
            MAX_RETAINED_DOCUMENT_CHANGES
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn open_hardens_document_store_file_and_directory_permissions() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("private").join("docs.json");

        let _store = DocumentStore::<Example>::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let file_mode = std::fs::metadata(&path)
            .unwrap_or_else(|error| panic!("{error}"))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);

        let parent = path.parent().unwrap_or_else(|| panic!("missing parent"));
        let directory_mode = std::fs::metadata(parent)
            .unwrap_or_else(|error| panic!("{error}"))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);
    }
}
