//! Shared metadata collection abstractions.
//!
//! Metadata collections are currently backed by [`DocumentStore<T>`] in
//! all-in-one mode, but service code depends on this thinner boundary so the
//! backing implementation can evolve without rewriting every consumer.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use uhost_core::{ErrorCode, PlatformError, Result, base64url_decode, base64url_encode};

use crate::document::{
    DocumentChange, DocumentChangePage, DocumentCursor, DocumentSnapshotCheckpoint, DocumentStore,
    StoredDocument,
};

const DEFAULT_METADATA_WATCH_POLL_INTERVAL: Duration = Duration::from_millis(250);
const METADATA_RESUME_TOKEN_PREFIX: &str = "v1:";

/// Boxed future returned by metadata backends.
pub type MetadataResultFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Stable cursor used to consume deterministic metadata changes.
pub type MetadataCursor = DocumentCursor;

/// One deterministic metadata mutation snapshot.
pub type MetadataChange<T> = DocumentChange<T>;

/// One ordered page of deterministic metadata changes.
pub type MetadataChangePage<T> = DocumentChangePage<T>;

/// Stable cursor used to paginate list results over a metadata collection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct MetadataListCursor {
    /// Last key returned by the previous page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_key: Option<String>,
}

impl MetadataListCursor {
    /// Return the origin cursor positioned before the first record.
    pub const fn origin() -> Self {
        Self { last_key: None }
    }
}

/// Optional list filter for one metadata collection scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataListFilter {
    /// Optional prefix that record keys must match.
    pub prefix: Option<String>,
    /// Whether soft-deleted records should be included.
    pub include_deleted: bool,
    /// Optional cursor from a previous page.
    pub cursor: Option<MetadataListCursor>,
    /// Maximum number of records to return in one page.
    pub limit: usize,
}

impl Default for MetadataListFilter {
    fn default() -> Self {
        Self {
            prefix: None,
            include_deleted: false,
            cursor: None,
            limit: 100,
        }
    }
}

/// One ordered page of metadata list results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataListPage<T> {
    /// Cursor to resume the scan when more records remain.
    pub next_cursor: Option<MetadataListCursor>,
    /// Records returned in this page.
    pub items: Vec<(String, StoredDocument<T>)>,
}

/// Point-in-time metadata snapshot used to reseed consumers after watch
/// compaction or bounded warm-start recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSnapshotCheckpoint<T> {
    /// Cursor positioned at the revision represented by this checkpoint.
    pub cursor: MetadataCursor,
    /// Opaque resume token equivalent to `cursor` for watch recovery.
    pub resume_token: MetadataResumeToken,
    /// Full record set at the checkpoint revision, including soft-deleted entries.
    pub records: BTreeMap<String, StoredDocument<T>>,
}

impl<T> MetadataSnapshotCheckpoint<T> {
    fn from_document_checkpoint(checkpoint: DocumentSnapshotCheckpoint<T>) -> Self {
        let cursor = checkpoint.cursor;
        Self {
            cursor,
            resume_token: MetadataResumeToken::from_cursor(cursor),
            records: checkpoint.records,
        }
    }
}

/// Result type returned by metadata watch operations.
pub type MetadataWatchResult<T> = std::result::Result<T, MetadataWatchError>;

/// Boxed future returned by metadata watch operations.
pub type MetadataWatchResultFuture<'a, T> =
    Pin<Box<dyn Future<Output = MetadataWatchResult<T>> + Send + 'a>>;

/// Opaque resume token used to continue metadata watches without replaying
/// already consumed revisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MetadataResumeToken(String);

impl MetadataResumeToken {
    /// Return the origin token positioned before the first mutation.
    pub fn origin() -> Self {
        Self::from_cursor(DocumentCursor::origin())
    }

    /// Return the raw encoded token string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_cursor(cursor: MetadataCursor) -> Self {
        let payload = format!("{METADATA_RESUME_TOKEN_PREFIX}{}", cursor.revision);
        Self(base64url_encode(payload.as_bytes()))
    }

    fn decode(&self) -> MetadataWatchResult<MetadataCursor> {
        let decoded = base64url_decode(&self.0).map_err(|error| {
            MetadataWatchError::invalid_resume_token(format!(
                "expected base64url-encoded `{METADATA_RESUME_TOKEN_PREFIX}<revision>` payload: {error}"
            ))
        })?;
        let decoded = String::from_utf8(decoded).map_err(|error| {
            MetadataWatchError::invalid_resume_token(format!(
                "expected UTF-8 `{METADATA_RESUME_TOKEN_PREFIX}<revision>` payload: {error}"
            ))
        })?;
        let Some(raw_revision) = decoded.strip_prefix(METADATA_RESUME_TOKEN_PREFIX) else {
            return Err(MetadataWatchError::invalid_resume_token(format!(
                "expected `{METADATA_RESUME_TOKEN_PREFIX}<revision>` payload"
            )));
        };
        let revision = raw_revision.parse::<u64>().map_err(|error| {
            MetadataWatchError::invalid_resume_token(format!(
                "failed to parse resume token revision: {error}"
            ))
        })?;
        Ok(MetadataCursor { revision })
    }
}

impl AsRef<str> for MetadataResumeToken {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for MetadataResumeToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One metadata watch request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataWatchRequest {
    /// Optional opaque token returned by a prior watch batch.
    ///
    /// When absent, the watch starts from the current collection revision and
    /// only yields future changes.
    pub resume_token: Option<MetadataResumeToken>,
    /// Maximum number of changes returned in one batch.
    pub limit: usize,
    /// Maximum amount of time to wait for at least one new change.
    ///
    /// A zero duration performs an immediate non-blocking read.
    pub idle_timeout: Duration,
}

impl MetadataWatchRequest {
    /// Build one watch request that starts from the current collection revision.
    pub fn new(limit: usize, idle_timeout: Duration) -> Self {
        Self {
            resume_token: None,
            limit,
            idle_timeout,
        }
    }

    /// Build one watch request that resumes from a previously issued token.
    pub fn from_resume_token(
        resume_token: MetadataResumeToken,
        limit: usize,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            resume_token: Some(resume_token),
            limit,
            idle_timeout,
        }
    }
}

/// Stable classification for one watched metadata mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataWatchEventKind {
    /// The mutation created or updated an active record.
    Upsert,
    /// The mutation soft-deleted a record.
    Delete,
}

/// One metadata mutation delivered by the watch adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize", deserialize = "T: Deserialize<'de>"))]
pub struct MetadataWatchEvent<T> {
    /// Collection revision assigned to this mutation.
    pub revision: u64,
    /// Stable record key mutated at this revision.
    pub key: String,
    /// Coarse event kind derived from the stored document state.
    pub kind: MetadataWatchEventKind,
    /// Persisted document snapshot after the mutation completed.
    pub document: StoredDocument<T>,
}

impl<T> MetadataWatchEvent<T> {
    fn from_change(change: MetadataChange<T>) -> Self {
        let kind = if change.document.deleted {
            MetadataWatchEventKind::Delete
        } else {
            MetadataWatchEventKind::Upsert
        };
        Self {
            revision: change.revision,
            key: change.key,
            kind,
            document: change.document,
        }
    }
}

/// One batch of watched metadata mutations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataWatchBatch<T> {
    /// Opaque token that should be persisted and supplied on the next watch.
    pub resume_token: MetadataResumeToken,
    /// Ordered metadata mutations observed for this batch.
    pub events: Vec<MetadataWatchEvent<T>>,
    /// Whether the watch completed without observing any new changes.
    pub idle: bool,
}

/// Typed errors returned by the metadata watch adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataWatchError {
    /// The selected backend does not implement metadata watches.
    UnsupportedBackend,
    /// The requested batch size is invalid.
    InvalidLimit,
    /// The supplied resume token could not be decoded.
    InvalidResumeToken(PlatformError),
    /// The supplied resume token is ahead of the current collection revision.
    ResumeTokenAhead {
        /// Resume token supplied by the caller.
        requested: MetadataResumeToken,
        /// Latest token currently available from the collection.
        current: MetadataResumeToken,
    },
    /// The supplied resume token points to history that has been compacted away.
    ResumeTokenCompacted {
        /// Resume token supplied by the caller.
        requested: MetadataResumeToken,
        /// Latest token currently available from the collection.
        current: MetadataResumeToken,
    },
    /// The underlying backend failed while serving the watch.
    Backend(PlatformError),
}

impl MetadataWatchError {
    /// Convert this watch error into the shared platform error shape.
    pub fn to_platform_error(&self) -> PlatformError {
        match self {
            Self::UnsupportedBackend => {
                PlatformError::unavailable("metadata watch is not supported by this backend")
            }
            Self::InvalidLimit => {
                PlatformError::invalid("metadata watch limit must be greater than zero")
            }
            Self::InvalidResumeToken(error) | Self::Backend(error) => error.clone(),
            Self::ResumeTokenAhead { requested, current } => PlatformError::conflict(
                "metadata resume token is ahead of the current collection revision",
            )
            .with_detail(format!("requested={requested}, current={current}")),
            Self::ResumeTokenCompacted { requested, current } => PlatformError::conflict(
                "metadata resume token has been compacted out of the retained change history",
            )
            .with_detail(format!(
                "requested={requested}, current={current}; reload collection state and resume from a fresh token"
            )),
        }
    }

    fn invalid_resume_token(detail: impl Into<String>) -> Self {
        Self::InvalidResumeToken(
            PlatformError::invalid("invalid metadata resume token").with_detail(detail),
        )
    }

    fn from_change_feed_error(
        error: PlatformError,
        requested: MetadataResumeToken,
        current: MetadataResumeToken,
    ) -> Self {
        if error.code == ErrorCode::Conflict {
            return Self::ResumeTokenCompacted { requested, current };
        }
        Self::Backend(error)
    }
}

impl fmt::Display for MetadataWatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_platform_error().fmt(formatter)
    }
}

impl std::error::Error for MetadataWatchError {}

impl From<PlatformError> for MetadataWatchError {
    fn from(error: PlatformError) -> Self {
        Self::Backend(error)
    }
}

/// Shared trait for document-oriented metadata collections.
pub trait MetadataStore<T>: Send + Sync + 'static
where
    T: Clone + Send + Sync + 'static,
{
    /// List all records, including soft-deleted entries.
    fn list(&self) -> MetadataResultFuture<'_, Vec<(String, StoredDocument<T>)>>;

    /// Fetch one record by key.
    fn get<'a>(&'a self, key: &'a str) -> MetadataResultFuture<'a, Option<StoredDocument<T>>>;

    /// Return the current change-feed cursor for metadata records.
    fn current_cursor(&self) -> MetadataResultFuture<'_, MetadataCursor>;

    /// Return one ordered page of metadata changes after the supplied cursor.
    fn changes_since(
        &self,
        cursor: Option<MetadataCursor>,
        limit: usize,
    ) -> MetadataResultFuture<'_, MetadataChangePage<T>>;

    /// Return one point-in-time checkpoint with a matching watch resume token.
    fn snapshot_checkpoint(&self) -> MetadataResultFuture<'_, MetadataSnapshotCheckpoint<T>> {
        Box::pin(async {
            Err(PlatformError::unavailable(
                "metadata snapshot checkpoints are not supported by this backend",
            ))
        })
    }

    /// Create a new record. Fails when the key already exists.
    fn create<'a>(&'a self, key: &'a str, value: T) -> MetadataResultFuture<'a, StoredDocument<T>>;

    /// Create or update a record with optimistic concurrency semantics.
    fn upsert<'a>(
        &'a self,
        key: &'a str,
        value: T,
        expected_version: Option<u64>,
    ) -> MetadataResultFuture<'a, StoredDocument<T>>;

    /// Soft-delete a record with optional optimistic concurrency checking.
    fn soft_delete<'a>(
        &'a self,
        key: &'a str,
        expected_version: Option<u64>,
    ) -> MetadataResultFuture<'a, ()>;

    /// Watch one ordered batch of changes after the supplied resume token.
    fn watch(
        &self,
        request: MetadataWatchRequest,
    ) -> MetadataWatchResultFuture<'_, MetadataWatchBatch<T>> {
        let _ = request;
        Box::pin(async { Err(MetadataWatchError::UnsupportedBackend) })
    }
}

impl<T> MetadataStore<T> for DocumentStore<T>
where
    T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
{
    fn list(&self) -> MetadataResultFuture<'_, Vec<(String, StoredDocument<T>)>> {
        Box::pin(async move { DocumentStore::list(self).await })
    }

    fn get<'a>(&'a self, key: &'a str) -> MetadataResultFuture<'a, Option<StoredDocument<T>>> {
        Box::pin(async move { DocumentStore::get(self, key).await })
    }

    fn current_cursor(&self) -> MetadataResultFuture<'_, MetadataCursor> {
        Box::pin(async move { DocumentStore::current_cursor(self).await })
    }

    fn changes_since(
        &self,
        cursor: Option<MetadataCursor>,
        limit: usize,
    ) -> MetadataResultFuture<'_, MetadataChangePage<T>> {
        Box::pin(async move { DocumentStore::changes_since(self, cursor, limit).await })
    }

    fn snapshot_checkpoint(&self) -> MetadataResultFuture<'_, MetadataSnapshotCheckpoint<T>> {
        Box::pin(async move {
            DocumentStore::snapshot_checkpoint(self)
                .await
                .map(MetadataSnapshotCheckpoint::from_document_checkpoint)
        })
    }

    fn create<'a>(&'a self, key: &'a str, value: T) -> MetadataResultFuture<'a, StoredDocument<T>> {
        Box::pin(async move { DocumentStore::create(self, key, value).await })
    }

    fn upsert<'a>(
        &'a self,
        key: &'a str,
        value: T,
        expected_version: Option<u64>,
    ) -> MetadataResultFuture<'a, StoredDocument<T>> {
        Box::pin(async move { DocumentStore::upsert(self, key, value, expected_version).await })
    }

    fn soft_delete<'a>(
        &'a self,
        key: &'a str,
        expected_version: Option<u64>,
    ) -> MetadataResultFuture<'a, ()> {
        Box::pin(async move { DocumentStore::soft_delete(self, key, expected_version).await })
    }

    fn watch(
        &self,
        request: MetadataWatchRequest,
    ) -> MetadataWatchResultFuture<'_, MetadataWatchBatch<T>> {
        Box::pin(async move {
            // Watch is a tailing API by default: no resume token starts from the
            // current cursor, zero idle timeout becomes a non-blocking poll, and
            // resume-token conflicts are surfaced as watch-specific errors so
            // callers can decide whether to restart from a newer token.
            if request.limit == 0 {
                return Err(MetadataWatchError::InvalidLimit);
            }

            let current_cursor = self
                .current_cursor()
                .await
                .map_err(MetadataWatchError::from)?;
            let resume_token = request.resume_token.clone();
            let requested_cursor = match resume_token.as_ref() {
                Some(token) => token.decode()?,
                None => current_cursor,
            };
            let requested_token =
                resume_token.unwrap_or_else(|| MetadataResumeToken::from_cursor(requested_cursor));

            if requested_cursor.revision > current_cursor.revision {
                return Err(MetadataWatchError::ResumeTokenAhead {
                    requested: requested_token,
                    current: MetadataResumeToken::from_cursor(current_cursor),
                });
            }

            let observed_cursor = if current_cursor.revision > requested_cursor.revision
                || request.idle_timeout.is_zero()
            {
                current_cursor
            } else {
                self.wait_for_revision_advance(
                    requested_cursor,
                    DEFAULT_METADATA_WATCH_POLL_INTERVAL,
                    request.idle_timeout,
                )
                .await
                .map_err(MetadataWatchError::from)?
            };

            if observed_cursor.revision == requested_cursor.revision {
                return Ok(MetadataWatchBatch {
                    resume_token: MetadataResumeToken::from_cursor(observed_cursor),
                    events: Vec::new(),
                    idle: true,
                });
            }

            let page = match self
                .changes_since(Some(requested_cursor), request.limit)
                .await
            {
                Ok(page) => page,
                Err(error) => {
                    let current_token = self
                        .current_cursor()
                        .await
                        .map(MetadataResumeToken::from_cursor)
                        .unwrap_or_else(|_| MetadataResumeToken::from_cursor(observed_cursor));
                    return Err(MetadataWatchError::from_change_feed_error(
                        error,
                        requested_token,
                        current_token,
                    ));
                }
            };
            Ok(MetadataWatchBatch {
                resume_token: MetadataResumeToken::from_cursor(page.next_cursor),
                events: page
                    .changes
                    .into_iter()
                    .map(MetadataWatchEvent::from_change)
                    .collect(),
                idle: false,
            })
        })
    }
}

/// Cloneable handle to a metadata backend.
#[derive(Clone)]
pub struct MetadataCollection<T>
where
    T: Clone + Send + Sync + 'static,
{
    inner: Arc<dyn MetadataStore<T>>,
    local_store: Option<DocumentStore<T>>,
}

impl<T> MetadataCollection<T>
where
    T: Clone + Send + Sync + 'static,
{
    /// Wrap a metadata backend behind the shared service-facing boundary.
    pub fn from_backend(backend: impl MetadataStore<T>) -> Self {
        Self {
            inner: Arc::new(backend),
            local_store: None,
        }
    }

    /// Wrap one local file-backed document store behind the shared metadata boundary.
    pub fn from_local_store(store: DocumentStore<T>) -> Self
    where
        T: DeserializeOwned + Serialize,
    {
        Self {
            inner: Arc::new(store.clone()),
            local_store: Some(store),
        }
    }

    /// Return the underlying local document store when this collection is file-backed.
    pub fn local_document_store(&self) -> Option<DocumentStore<T>> {
        self.local_store.clone()
    }

    /// List all records, including soft-deleted entries.
    pub async fn list(&self) -> Result<Vec<(String, StoredDocument<T>)>> {
        self.inner.list().await
    }

    /// Fetch one record by key.
    pub async fn get(&self, key: &str) -> Result<Option<StoredDocument<T>>> {
        self.inner.get(key).await
    }

    /// Return the current deterministic change-feed cursor for this collection.
    pub async fn current_cursor(&self) -> Result<MetadataCursor> {
        self.inner.current_cursor().await
    }

    /// Return one ordered page of changes strictly after the supplied cursor.
    pub async fn changes_since(
        &self,
        cursor: Option<MetadataCursor>,
        limit: usize,
    ) -> Result<MetadataChangePage<T>> {
        self.inner.changes_since(cursor, limit).await
    }

    /// Return one snapshot checkpoint with a matching watch resume token.
    pub async fn snapshot_checkpoint(&self) -> Result<MetadataSnapshotCheckpoint<T>> {
        self.inner.snapshot_checkpoint().await
    }

    /// Create a new record. Fails when the key already exists.
    pub async fn create(&self, key: &str, value: T) -> Result<StoredDocument<T>> {
        self.inner.create(key, value).await
    }

    /// Create or update a record with optimistic concurrency semantics.
    pub async fn upsert(
        &self,
        key: &str,
        value: T,
        expected_version: Option<u64>,
    ) -> Result<StoredDocument<T>> {
        self.inner.upsert(key, value, expected_version).await
    }

    /// Soft-delete a record with optional optimistic concurrency checking.
    pub async fn soft_delete(&self, key: &str, expected_version: Option<u64>) -> Result<()> {
        self.inner.soft_delete(key, expected_version).await
    }

    /// Return one filtered list page using a stable key cursor.
    pub async fn list_filtered(&self, filter: MetadataListFilter) -> Result<MetadataListPage<T>> {
        if filter.limit == 0 {
            return Err(PlatformError::invalid(
                "metadata list limit must be greater than zero",
            ));
        }

        let limit = filter.limit;
        let prefix = filter.prefix.as_deref();
        let cursor_key = filter
            .cursor
            .as_ref()
            .and_then(|cursor| cursor.last_key.as_deref());
        let mut records = self
            .list()
            .await?
            .into_iter()
            .filter(|(_, document)| filter.include_deleted || !document.deleted)
            .filter(|(key, _)| prefix.is_none_or(|value| key.starts_with(value)))
            .filter(|(key, _)| cursor_key.is_none_or(|cursor_key| key.as_str() > cursor_key))
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.0.cmp(&right.0));

        let mut items = records
            .into_iter()
            .take(limit.saturating_add(1))
            .collect::<Vec<_>>();
        let has_more = items.len() > limit;
        if has_more {
            items.truncate(limit);
        }
        let next_cursor = has_more.then(|| MetadataListCursor {
            last_key: items.last().map(|(key, _)| key.clone()),
        });

        Ok(MetadataListPage { next_cursor, items })
    }

    /// Watch one ordered batch of metadata changes.
    pub async fn watch(
        &self,
        request: MetadataWatchRequest,
    ) -> MetadataWatchResult<MetadataWatchBatch<T>> {
        self.inner.watch(request).await
    }

    /// Build one reusable watch adapter for this collection.
    pub fn watcher(&self, limit: usize, idle_timeout: Duration) -> MetadataWatcher<T> {
        MetadataWatcher::new(self.clone(), limit, idle_timeout)
    }
}

impl<T> MetadataCollection<T>
where
    T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
{
    /// Open the default file-backed metadata backend for all-in-one mode.
    pub async fn open_local(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::from_local_store(DocumentStore::open(path).await?))
    }
}

/// Cloneable adapter that maintains the latest resume token across watch calls.
#[derive(Debug, Clone)]
pub struct MetadataWatcher<T>
where
    T: Clone + Send + Sync + 'static,
{
    collection: MetadataCollection<T>,
    limit: usize,
    idle_timeout: Duration,
    resume_token: Option<MetadataResumeToken>,
}

impl<T> MetadataWatcher<T>
where
    T: Clone + Send + Sync + 'static,
{
    /// Create one new metadata watcher for the supplied collection.
    pub fn new(collection: MetadataCollection<T>, limit: usize, idle_timeout: Duration) -> Self {
        Self {
            collection,
            limit,
            idle_timeout,
            resume_token: None,
        }
    }

    /// Resume this watcher from one previously issued token.
    pub fn resume_from(mut self, resume_token: MetadataResumeToken) -> Self {
        self.resume_token = Some(resume_token);
        self
    }

    /// Start this watcher from the origin revision instead of the current revision.
    pub fn start_from_origin(mut self) -> Self {
        self.resume_token = Some(MetadataResumeToken::origin());
        self
    }

    /// Return the most recent resume token observed by this watcher.
    pub fn resume_token(&self) -> Option<&MetadataResumeToken> {
        self.resume_token.as_ref()
    }

    /// Read the next watch batch and retain its resume token locally.
    pub async fn next(&mut self) -> MetadataWatchResult<MetadataWatchBatch<T>> {
        let batch = self
            .collection
            .watch(MetadataWatchRequest {
                resume_token: self.resume_token.clone(),
                limit: self.limit,
                idle_timeout: self.idle_timeout,
            })
            .await?;
        self.resume_token = Some(batch.resume_token.clone());
        Ok(batch)
    }
}

impl<T> fmt::Debug for MetadataCollection<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let backend = if self.local_store.is_some() {
            "local_document_store"
        } else {
            "dyn MetadataStore"
        };
        formatter
            .debug_struct("MetadataCollection")
            .field("backend", &backend)
            .field("local_store", &self.local_store.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use serde::{Deserialize, Serialize};
    use tempfile::tempdir;

    use uhost_core::{ErrorCode, PlatformError};

    use super::{
        MetadataChangePage, MetadataCollection, MetadataListCursor, MetadataListFilter,
        MetadataResultFuture, MetadataResumeToken, MetadataSnapshotCheckpoint, MetadataStore,
        MetadataWatchError, MetadataWatchEventKind, MetadataWatchRequest,
    };
    use crate::document::{DocumentCursor, StoredDocument};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Example {
        name: String,
    }

    #[test]
    fn crate_root_reexports_metadata_snapshot_checkpoint() {
        let root_checkpoint: Option<crate::MetadataSnapshotCheckpoint<Example>> = None;
        let _module_checkpoint: Option<super::MetadataSnapshotCheckpoint<Example>> =
            root_checkpoint;
    }

    #[derive(Debug, Clone, Copy)]
    struct UnsupportedMetadataBackend;

    impl MetadataStore<Example> for UnsupportedMetadataBackend {
        fn list(&self) -> MetadataResultFuture<'_, Vec<(String, StoredDocument<Example>)>> {
            Box::pin(async { Err(unused_backend_method_error()) })
        }

        fn get<'a>(
            &'a self,
            _key: &'a str,
        ) -> MetadataResultFuture<'a, Option<StoredDocument<Example>>> {
            Box::pin(async { Err(unused_backend_method_error()) })
        }

        fn current_cursor(&self) -> MetadataResultFuture<'_, DocumentCursor> {
            Box::pin(async { Err(unused_backend_method_error()) })
        }

        fn changes_since(
            &self,
            _cursor: Option<DocumentCursor>,
            _limit: usize,
        ) -> MetadataResultFuture<'_, MetadataChangePage<Example>> {
            Box::pin(async { Err(unused_backend_method_error()) })
        }

        fn create<'a>(
            &'a self,
            _key: &'a str,
            _value: Example,
        ) -> MetadataResultFuture<'a, StoredDocument<Example>> {
            Box::pin(async { Err(unused_backend_method_error()) })
        }

        fn upsert<'a>(
            &'a self,
            _key: &'a str,
            _value: Example,
            _expected_version: Option<u64>,
        ) -> MetadataResultFuture<'a, StoredDocument<Example>> {
            Box::pin(async { Err(unused_backend_method_error()) })
        }

        fn soft_delete<'a>(
            &'a self,
            _key: &'a str,
            _expected_version: Option<u64>,
        ) -> MetadataResultFuture<'a, ()> {
            Box::pin(async { Err(unused_backend_method_error()) })
        }
    }

    fn unused_backend_method_error() -> PlatformError {
        PlatformError::unavailable("unused metadata backend method")
    }

    #[tokio::test]
    async fn local_metadata_collection_reads_and_writes_documents() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let collection = MetadataCollection::<Example>::open_local(temp.path().join("docs.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        collection
            .create(
                "alpha",
                Example {
                    name: String::from("primary"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let loaded = collection
            .get("alpha")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing document"));
        assert_eq!(loaded.value.name, "primary");
    }

    #[tokio::test]
    async fn local_metadata_collection_preserves_cross_handle_concurrency_checks() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("docs.json");
        let collection_a = MetadataCollection::<Example>::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_b = MetadataCollection::<Example>::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let created = collection_a
            .create(
                "alpha",
                Example {
                    name: String::from("one"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let updated = collection_b
            .upsert(
                "alpha",
                Example {
                    name: String::from("two"),
                },
                Some(created.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(updated.version, created.version + 1);

        let stale = collection_a
            .upsert(
                "alpha",
                Example {
                    name: String::from("stale"),
                },
                Some(created.version),
            )
            .await
            .expect_err("stale version should fail");
        assert_eq!(stale.code, ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn metadata_list_filtered_pages_by_key_prefix_without_deleted_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let collection = MetadataCollection::<Example>::open_local(temp.path().join("docs.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        for (key, name) in [
            ("app-alpha", "one"),
            ("app-bravo", "two"),
            ("app-charlie", "three"),
            ("user-delta", "four"),
        ] {
            collection
                .create(
                    key,
                    Example {
                        name: String::from(name),
                    },
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let bravo = collection
            .get("app-bravo")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing document"));
        collection
            .soft_delete("app-bravo", Some(bravo.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first_page = collection
            .list_filtered(MetadataListFilter {
                prefix: Some(String::from("app-")),
                include_deleted: false,
                cursor: None,
                limit: 1,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first_page.items.len(), 1);
        assert_eq!(first_page.items[0].0, "app-alpha");
        assert_eq!(
            first_page.next_cursor,
            Some(MetadataListCursor {
                last_key: Some(String::from("app-alpha")),
            })
        );

        let second_page = collection
            .list_filtered(MetadataListFilter {
                prefix: Some(String::from("app-")),
                include_deleted: false,
                cursor: first_page.next_cursor.clone(),
                limit: 1,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second_page.items.len(), 1);
        assert_eq!(second_page.items[0].0, "app-charlie");
        assert!(second_page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn metadata_list_filtered_can_include_deleted_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let collection = MetadataCollection::<Example>::open_local(temp.path().join("docs.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        collection
            .create(
                "app-alpha",
                Example {
                    name: String::from("one"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let bravo = collection
            .create(
                "app-bravo",
                Example {
                    name: String::from("two"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        collection
            .soft_delete("app-bravo", Some(bravo.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let page = collection
            .list_filtered(MetadataListFilter {
                prefix: Some(String::from("app-")),
                include_deleted: true,
                cursor: Some(MetadataListCursor::origin()),
                limit: 10,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].0, "app-alpha");
        assert_eq!(page.items[1].0, "app-bravo");
        assert!(page.items[1].1.deleted);
        assert!(page.next_cursor.is_none());
    }

    #[tokio::test]
    async fn metadata_list_filtered_rejects_zero_limit() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let collection = MetadataCollection::<Example>::open_local(temp.path().join("docs.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = collection
            .list_filtered(MetadataListFilter {
                limit: 0,
                ..MetadataListFilter::default()
            })
            .await
            .expect_err("zero limit should fail");
        assert_eq!(error.code, ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn metadata_snapshot_checkpoint_reports_unsupported_backend_errors() {
        let collection = MetadataCollection::from_backend(UnsupportedMetadataBackend);

        let error = collection
            .snapshot_checkpoint()
            .await
            .expect_err("unsupported backend should fail");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert_eq!(
            error.message,
            "metadata snapshot checkpoints are not supported by this backend"
        );
    }

    #[tokio::test]
    async fn metadata_snapshot_checkpoint_includes_cursor_resume_token_and_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let collection = MetadataCollection::<Example>::open_local(temp.path().join("docs.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        collection
            .create(
                "alpha",
                Example {
                    name: String::from("one"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let bravo = collection
            .create(
                "bravo",
                Example {
                    name: String::from("two"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        collection
            .soft_delete("bravo", Some(bravo.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let checkpoint = collection
            .snapshot_checkpoint()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(checkpoint.cursor, DocumentCursor { revision: 3 });
        assert_eq!(
            checkpoint.resume_token,
            MetadataResumeToken::from_cursor(checkpoint.cursor)
        );
        assert_eq!(checkpoint.records.len(), 2);
        assert_eq!(
            checkpoint
                .records
                .get("alpha")
                .unwrap_or_else(|| panic!("missing alpha"))
                .value
                .name,
            "one"
        );
        assert!(
            checkpoint
                .records
                .get("bravo")
                .unwrap_or_else(|| panic!("missing bravo"))
                .deleted
        );
    }

    #[tokio::test]
    async fn metadata_watch_rejects_zero_limit() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let collection = MetadataCollection::<Example>::open_local(temp.path().join("docs.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = collection
            .watch(MetadataWatchRequest::new(0, Duration::ZERO))
            .await
            .expect_err("zero watch limit should fail");
        assert!(matches!(error, MetadataWatchError::InvalidLimit));
        assert_eq!(error.to_platform_error().code, ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn metadata_watch_reports_unsupported_backend_errors() {
        let collection = MetadataCollection::from_backend(UnsupportedMetadataBackend);

        let error = collection
            .watch(MetadataWatchRequest::new(1, Duration::ZERO))
            .await
            .expect_err("unsupported backend should fail");
        assert!(matches!(error, MetadataWatchError::UnsupportedBackend));
        assert_eq!(
            error.to_platform_error().message,
            "metadata watch is not supported by this backend"
        );
    }

    #[tokio::test]
    async fn metadata_watcher_preserves_resume_token_on_watch_error() {
        let collection = MetadataCollection::from_backend(UnsupportedMetadataBackend);
        let mut watcher = collection.watcher(1, Duration::ZERO).start_from_origin();
        let expected_token = watcher
            .resume_token()
            .cloned()
            .unwrap_or_else(|| panic!("missing resume token"));

        let error = watcher
            .next()
            .await
            .expect_err("unsupported backend should fail");
        assert!(matches!(error, MetadataWatchError::UnsupportedBackend));
        assert_eq!(watcher.resume_token(), Some(&expected_token));
    }

    #[tokio::test]
    async fn metadata_watch_replays_changes_from_resume_token() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let collection = MetadataCollection::<Example>::open_local(temp.path().join("docs.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        collection
            .create(
                "alpha",
                Example {
                    name: String::from("one"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        collection
            .create(
                "bravo",
                Example {
                    name: String::from("two"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first = collection
            .watch(MetadataWatchRequest::from_resume_token(
                MetadataResumeToken::origin(),
                1,
                Duration::ZERO,
            ))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!first.idle);
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.events[0].key, "alpha");
        assert_eq!(first.events[0].kind, MetadataWatchEventKind::Upsert);

        let second = collection
            .watch(MetadataWatchRequest::from_resume_token(
                first.resume_token.clone(),
                10,
                Duration::ZERO,
            ))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!second.idle);
        assert_eq!(second.events.len(), 1);
        assert_eq!(second.events[0].key, "bravo");
        assert_eq!(
            second.resume_token,
            MetadataResumeToken::from_cursor(DocumentCursor { revision: 2 })
        );
    }

    #[tokio::test]
    async fn metadata_watch_rejects_invalid_resume_tokens() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let collection = MetadataCollection::<Example>::open_local(temp.path().join("docs.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = collection
            .watch(MetadataWatchRequest::from_resume_token(
                MetadataResumeToken(String::from("Zm9v")),
                10,
                Duration::ZERO,
            ))
            .await
            .expect_err("invalid token should fail");
        match error {
            MetadataWatchError::InvalidResumeToken(platform_error) => {
                assert_eq!(platform_error.code, ErrorCode::InvalidInput);
                assert_eq!(platform_error.message, "invalid metadata resume token");
                assert!(
                    platform_error
                        .detail
                        .as_deref()
                        .is_some_and(|detail| detail.contains("v1:<revision>"))
                );
            }
            other => panic!("unexpected watch error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn metadata_watch_rejects_resume_tokens_ahead_of_collection() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let collection = MetadataCollection::<Example>::open_local(temp.path().join("docs.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        collection
            .create(
                "alpha",
                Example {
                    name: String::from("one"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let requested = MetadataResumeToken::from_cursor(DocumentCursor { revision: 9 });
        let error = collection
            .watch(MetadataWatchRequest::from_resume_token(
                requested.clone(),
                10,
                Duration::ZERO,
            ))
            .await
            .expect_err("ahead token should fail");
        match error {
            MetadataWatchError::ResumeTokenAhead {
                requested: actual_requested,
                current,
            } => {
                assert_eq!(actual_requested, requested);
                assert_eq!(
                    current,
                    MetadataResumeToken::from_cursor(DocumentCursor { revision: 1 })
                );
            }
            other => panic!("unexpected watch error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn metadata_watch_reports_compacted_resume_tokens() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let collection = MetadataCollection::<Example>::open_local(temp.path().join("docs.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let store = collection
            .local_document_store()
            .unwrap_or_else(|| panic!("missing local document store"));

        let mut next_index = 0usize;
        loop {
            let key = format!("doc-{next_index}");
            collection
                .create(
                    key.as_str(),
                    Example {
                        name: format!("name-{next_index}"),
                    },
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            next_index += 1;

            let snapshot = store
                .snapshot_collection()
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            if snapshot.compacted_through_revision > 0 {
                break;
            }
            assert!(
                next_index <= 300,
                "failed to trigger document change compaction"
            );
        }

        let current = collection
            .current_cursor()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let error = collection
            .watch(MetadataWatchRequest::from_resume_token(
                MetadataResumeToken::origin(),
                10,
                Duration::ZERO,
            ))
            .await
            .expect_err("compacted resume token should fail");
        let platform_error = error.to_platform_error();
        match error {
            MetadataWatchError::ResumeTokenCompacted {
                requested,
                current: actual_current,
            } => {
                assert_eq!(requested, MetadataResumeToken::origin());
                assert_eq!(actual_current, MetadataResumeToken::from_cursor(current));
            }
            other => panic!("unexpected watch error: {other:?}"),
        }
        assert_eq!(platform_error.code, ErrorCode::Conflict);
        assert_eq!(
            platform_error.message,
            "metadata resume token has been compacted out of the retained change history"
        );
        assert!(platform_error.detail.as_deref().is_some_and(|detail| {
            detail.contains("reload collection state")
                && detail.contains(MetadataResumeToken::origin().as_str())
        }));
    }

    #[tokio::test]
    async fn metadata_snapshot_checkpoint_reseeds_after_compacted_watch_tokens() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let collection = MetadataCollection::<Example>::open_local(temp.path().join("docs.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let store = collection
            .local_document_store()
            .unwrap_or_else(|| panic!("missing local document store"));

        let mut next_index = 0usize;
        loop {
            let key = format!("doc-{next_index}");
            collection
                .create(
                    key.as_str(),
                    Example {
                        name: format!("name-{next_index}"),
                    },
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            next_index += 1;

            let snapshot = store
                .snapshot_collection()
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            if snapshot.compacted_through_revision > 0 {
                break;
            }
            assert!(
                next_index <= 300,
                "failed to trigger document change compaction"
            );
        }

        let current_token = match collection
            .watch(MetadataWatchRequest::from_resume_token(
                MetadataResumeToken::origin(),
                10,
                Duration::ZERO,
            ))
            .await
            .expect_err("compacted resume token should fail")
        {
            MetadataWatchError::ResumeTokenCompacted { current, .. } => current,
            other => panic!("unexpected watch error: {other:?}"),
        };

        let checkpoint: MetadataSnapshotCheckpoint<Example> = collection
            .snapshot_checkpoint()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(checkpoint.resume_token, current_token);
        assert_eq!(checkpoint.records.len(), next_index);

        let idle = collection
            .watch(MetadataWatchRequest::from_resume_token(
                checkpoint.resume_token.clone(),
                10,
                Duration::ZERO,
            ))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(idle.idle);
        assert!(idle.events.is_empty());

        collection
            .create(
                "post-checkpoint",
                Example {
                    name: String::from("new"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let resumed = collection
            .watch(MetadataWatchRequest::from_resume_token(
                checkpoint.resume_token,
                10,
                Duration::ZERO,
            ))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!resumed.idle);
        assert_eq!(resumed.events.len(), 1);
        assert_eq!(resumed.events[0].key, "post-checkpoint");
        assert_eq!(resumed.events[0].document.value.name, "new");
    }

    #[tokio::test]
    async fn metadata_watcher_updates_its_resume_token_across_batches() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let collection = MetadataCollection::<Example>::open_local(temp.path().join("docs.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        collection
            .create(
                "alpha",
                Example {
                    name: String::from("one"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        collection
            .create(
                "bravo",
                Example {
                    name: String::from("two"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut watcher = collection.watcher(1, Duration::ZERO).start_from_origin();
        let first = watcher
            .next()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.events[0].key, "alpha");
        assert_eq!(watcher.resume_token(), Some(&first.resume_token));

        let second = watcher
            .next()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second.events.len(), 1);
        assert_eq!(second.events[0].key, "bravo");
        assert_eq!(watcher.resume_token(), Some(&second.resume_token));
    }

    #[tokio::test]
    async fn metadata_watch_waits_for_new_changes_from_current_revision() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("docs.json");
        let collection_a = MetadataCollection::<Example>::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_b = MetadataCollection::<Example>::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let bootstrap = collection_a
            .watch(MetadataWatchRequest::new(10, Duration::ZERO))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(bootstrap.idle);

        let mut watcher = collection_a
            .watcher(10, Duration::from_secs(1))
            .resume_from(bootstrap.resume_token);
        let started_at = Instant::now();
        let watch_task = tokio::spawn(async move { watcher.next().await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        collection_b
            .create(
                "alpha",
                Example {
                    name: String::from("one"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let batch = watch_task
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!batch.idle);
        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.events[0].key, "alpha");
        assert!(started_at.elapsed() < Duration::from_millis(900));
    }
}
