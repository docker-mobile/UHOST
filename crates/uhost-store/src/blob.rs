//! Content-addressed blob store.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, SeekFrom};
use tokio::sync::Mutex;

use uhost_core::{PlatformError, Result, sha256_hex};

/// Metadata returned for stored blobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobMetadata {
    /// SHA-256 content digest.
    pub digest: String,
    /// Blob size in bytes.
    pub size: u64,
}

/// Result of storing or composing a blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobWriteOutcome {
    /// Metadata for the canonical blob.
    pub metadata: BlobMetadata,
    /// Whether this call published a new blob instead of reusing an existing one.
    pub created_new: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BlobIntegritySidecar {
    algorithm: String,
    digest: String,
    size: u64,
}

impl BlobIntegritySidecar {
    const ALGORITHM: &str = "sha256";

    fn from_metadata(metadata: &BlobMetadata) -> Self {
        Self {
            algorithm: String::from(Self::ALGORITHM),
            digest: metadata.digest.clone(),
            size: metadata.size,
        }
    }

    fn validate(&self, metadata: &BlobMetadata) -> Result<()> {
        if self.algorithm != Self::ALGORITHM
            || self.digest != metadata.digest
            || self.size != metadata.size
        {
            return Err(
                PlatformError::unavailable("blob integrity sidecar mismatch").with_detail(
                    format!(
                        "expected_digest={} expected_size={} actual_digest={} actual_size={} algorithm={}",
                        metadata.digest,
                        metadata.size,
                        self.digest,
                        self.size,
                        self.algorithm
                    ),
                ),
            );
        }
        Ok(())
    }
}

/// How one blob was materialized in the local store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobLineageKind {
    /// Directly written payload.
    Direct,
    /// Concatenated or otherwise assembled from existing parts.
    Composed,
}

/// Durable provenance and source blobs for one stored object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobLineage {
    /// Materialization strategy that produced this blob.
    pub kind: BlobLineageKind,
    /// Source digests used when the blob was composed from existing parts.
    #[serde(default)]
    pub source_digests: Vec<String>,
}

impl BlobLineage {
    fn direct() -> Self {
        Self {
            kind: BlobLineageKind::Direct,
            source_digests: Vec::new(),
        }
    }

    fn composed(source_digests: &[String]) -> Self {
        Self {
            kind: BlobLineageKind::Composed,
            source_digests: source_digests.to_vec(),
        }
    }
}

/// Durable owner class retaining one blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobReferenceKind {
    /// Stable external ownership for a published or otherwise durable blob.
    DurableRoot,
    /// Multipart upload staging ownership for one uploaded part or assembled object.
    MultipartUpload,
    /// Compose or assembly workflow ownership for an intermediate blob.
    ComposeOperation,
    /// Temporary hold that blocks collection during explicit GC review.
    GarbageCollectionHold,
}

/// One durable owner retaining one blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobReferenceEntry {
    /// Reference category retaining the blob.
    pub kind: BlobReferenceKind,
    /// First time the reference was created.
    pub created_at: OffsetDateTime,
    /// Most recent refresh for the reference.
    pub updated_at: OffsetDateTime,
}

/// Durable blob reference state used to decide whether one blob is orphaned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobReferenceState {
    /// Metadata for the underlying physical blob.
    pub metadata: BlobMetadata,
    /// Durable provenance for how the blob was materialized.
    pub lineage: BlobLineage,
    /// Reference kinds that have retained this blob over time.
    #[serde(default)]
    pub observed_reference_kinds: Vec<BlobReferenceKind>,
    /// Active durable references keyed by caller-supplied reference id.
    #[serde(default)]
    pub references: BTreeMap<String, BlobReferenceEntry>,
    /// Time when the blob was last collected by the orphan GC workflow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_collected_at: Option<OffsetDateTime>,
}

impl BlobReferenceState {
    fn new(metadata: &BlobMetadata, lineage: BlobLineage) -> Self {
        Self {
            metadata: metadata.clone(),
            lineage,
            observed_reference_kinds: Vec::new(),
            references: BTreeMap::new(),
            last_collected_at: None,
        }
    }

    fn merge_lineage(&mut self, lineage: BlobLineage) {
        match (self.lineage.kind, lineage.kind) {
            (BlobLineageKind::Composed, BlobLineageKind::Direct) => {}
            _ => self.lineage = lineage,
        }
    }

    fn remember_kind(&mut self, kind: BlobReferenceKind) {
        if !self.observed_reference_kinds.contains(&kind) {
            self.observed_reference_kinds.push(kind);
            self.observed_reference_kinds.sort();
        }
    }

    fn orphan_reason(&self) -> Option<&'static str> {
        if !self.references.is_empty() {
            return None;
        }
        if matches!(self.lineage.kind, BlobLineageKind::Composed) {
            return Some("orphaned composed blob");
        }
        if self.observed_reference_kinds.iter().any(|kind| {
            matches!(
                kind,
                BlobReferenceKind::MultipartUpload | BlobReferenceKind::ComposeOperation
            )
        }) {
            return Some("orphaned multipart or compose-staging blob");
        }
        None
    }

    fn should_persist(&self) -> bool {
        !self.references.is_empty() || self.orphan_reason().is_some()
    }
}

/// One orphaned blob selected for collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobGcCandidate {
    /// Digest for the blob candidate.
    pub digest: String,
    /// Current physical size in bytes.
    pub size: u64,
    /// Durable lineage carried with the candidate.
    pub lineage: BlobLineage,
    /// Human-readable reason the blob qualified for collection.
    pub reason: String,
}

/// Phase for one durable blob GC workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobGcWorkflowPhase {
    /// Candidate set was persisted but not yet executed.
    Planned,
    /// Candidate set has been executed and outcomes were persisted.
    Completed,
}

/// Durable orphan-GC workflow for multipart or composed blobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobGcWorkflow {
    /// Stable workflow identifier.
    pub id: String,
    /// Time when the workflow was created.
    pub created_at: OffsetDateTime,
    /// Completion time when the workflow finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<OffsetDateTime>,
    /// Current execution phase.
    pub phase: BlobGcWorkflowPhase,
    /// Candidate blobs considered during this run.
    pub candidates: Vec<BlobGcCandidate>,
    /// Candidates actually deleted after revalidation.
    #[serde(default)]
    pub deleted_digests: Vec<String>,
    /// Candidates skipped because they were no longer orphaned or already absent.
    #[serde(default)]
    pub skipped_digests: Vec<String>,
}

impl BlobGcWorkflow {
    fn new(candidates: Vec<BlobGcCandidate>) -> Self {
        Self {
            id: next_blob_gc_workflow_id(),
            created_at: OffsetDateTime::now_utc(),
            completed_at: None,
            phase: BlobGcWorkflowPhase::Planned,
            candidates,
            deleted_digests: Vec::new(),
            skipped_digests: Vec::new(),
        }
    }
}

/// File-backed content-addressed blob store.
#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
    accounting_guard: Arc<Mutex<()>>,
}

const BLOB_STREAM_CHUNK_SIZE: usize = 64 * 1024;

impl BlobStore {
    /// Open or create a blob store.
    pub async fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).await.map_err(|error| {
            PlatformError::unavailable("failed to create blob store directory")
                .with_detail(error.to_string())
        })?;
        Ok(Self {
            accounting_guard: shared_blob_accounting_guard(&root),
            root,
        })
    }

    /// Store bytes by digest and return metadata.
    pub async fn put(&self, payload: Bytes) -> Result<BlobMetadata> {
        self.put_with_status(payload)
            .await
            .map(|outcome| outcome.metadata)
    }

    /// Store bytes by digest and report whether this call created the blob.
    pub async fn put_with_status(&self, payload: Bytes) -> Result<BlobWriteOutcome> {
        let digest = sha256_hex(&payload);
        let path = self.path_for_digest(&digest)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(|error| {
                PlatformError::unavailable("failed to create blob shard directory")
                    .with_detail(error.to_string())
            })?;
        }
        match fs::metadata(&path).await {
            Ok(metadata) => {
                let metadata = BlobMetadata {
                    digest: digest.clone(),
                    size: metadata.len(),
                };
                self.ensure_integrity_sidecar(&path, &metadata).await?;
                self.sync_reference_state(&metadata, BlobLineage::direct())
                    .await?;
                return Ok(BlobWriteOutcome {
                    metadata,
                    created_new: false,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(
                    PlatformError::unavailable("failed to stat blob before write")
                        .with_detail(error.to_string()),
                );
            }
        }

        let temp_path = unique_temp_path(&self.root, "blob");
        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(parent).await.map_err(|error| {
                PlatformError::unavailable("failed to create blob temp directory")
                    .with_detail(error.to_string())
            })?;
        }

        let result = async {
            let mut temp_file = tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp_path)
                .await
                .map_err(|error| {
                    PlatformError::unavailable("failed to create blob temp file")
                        .with_detail(error.to_string())
                })?;
            temp_file.write_all(&payload).await.map_err(|error| {
                PlatformError::unavailable("failed to persist blob").with_detail(error.to_string())
            })?;
            temp_file.flush().await.map_err(|error| {
                PlatformError::unavailable("failed to flush blob temp file")
                    .with_detail(error.to_string())
            })?;
            temp_file.sync_all().await.map_err(|error| {
                PlatformError::unavailable("failed to sync blob temp file")
                    .with_detail(error.to_string())
            })?;
            drop(temp_file);

            if let Err(error) = fs::rename(&temp_path, &path).await {
                if let Ok(metadata) = fs::metadata(&path).await {
                    let _ = fs::remove_file(&temp_path).await;
                    let metadata = BlobMetadata {
                        digest: digest.clone(),
                        size: metadata.len(),
                    };
                    self.ensure_integrity_sidecar(&path, &metadata).await?;
                    self.sync_reference_state(&metadata, BlobLineage::direct())
                        .await?;
                    return Ok(BlobWriteOutcome {
                        metadata,
                        created_new: false,
                    });
                }
                return Err(PlatformError::unavailable("failed to commit blob")
                    .with_detail(error.to_string()));
            }
            sync_path_parent(&path).await?;

            let metadata = BlobMetadata {
                digest,
                size: payload.len() as u64,
            };
            self.ensure_integrity_sidecar(&path, &metadata).await?;
            self.sync_reference_state(&metadata, BlobLineage::direct())
                .await?;
            Ok(BlobWriteOutcome {
                metadata,
                created_new: true,
            })
        }
        .await;

        if result.is_err() {
            let _ = fs::remove_file(&temp_path).await;
        }
        result
    }

    /// Return verified metadata for a stored blob.
    pub async fn metadata(&self, digest: &str) -> Result<Option<BlobMetadata>> {
        let digest = canonicalize_digest(digest)?;
        let path = self.path_for_digest(&digest)?;
        let file_metadata = match fs::metadata(&path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(PlatformError::unavailable("failed to stat blob")
                    .with_detail(error.to_string()));
            }
        };

        let metadata = BlobMetadata {
            digest,
            size: file_metadata.len(),
        };
        self.ensure_integrity_sidecar(&path, &metadata).await?;
        Ok(Some(metadata))
    }

    /// Read a stored blob.
    pub async fn get(&self, digest: &str) -> Result<Option<Bytes>> {
        let Some(metadata) = self.metadata(digest).await? else {
            return Ok(None);
        };
        let path = self.path_for_digest(&metadata.digest)?;
        self.read_blob_bytes(&path, &metadata.digest, 0, metadata.size)
            .await
            .map(Some)
    }

    /// Stream a stored blob into an async writer without buffering the full object in memory.
    pub async fn stream_to<W>(&self, digest: &str, writer: &mut W) -> Result<Option<BlobMetadata>>
    where
        W: AsyncWrite + Unpin,
    {
        let Some(metadata) = self.metadata(digest).await? else {
            return Ok(None);
        };
        let path = self.path_for_digest(&metadata.digest)?;
        self.stream_blob_bytes(&path, &metadata.digest, 0, metadata.size, writer)
            .await?;
        Ok(Some(metadata))
    }

    /// Read a verified byte range from a stored blob.
    pub async fn get_range(
        &self,
        digest: &str,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Option<Bytes>> {
        let Some(metadata) = self.metadata(digest).await? else {
            return Ok(None);
        };
        if start > end_inclusive || end_inclusive >= metadata.size {
            return Err(
                PlatformError::invalid("invalid blob byte range").with_detail(format!(
                    "digest={} start={start} end={end_inclusive} size={}",
                    metadata.digest, metadata.size
                )),
            );
        }

        let length = end_inclusive
            .checked_sub(start)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| PlatformError::unavailable("blob range length overflowed"))?;
        let path = self.path_for_digest(&metadata.digest)?;
        self.read_blob_bytes(&path, &metadata.digest, start, length)
            .await
            .map(Some)
    }

    /// Stream a verified byte range into an async writer without buffering the full range.
    pub async fn stream_range_to<W>(
        &self,
        digest: &str,
        start: u64,
        end_inclusive: u64,
        writer: &mut W,
    ) -> Result<Option<BlobMetadata>>
    where
        W: AsyncWrite + Unpin,
    {
        let Some(metadata) = self.metadata(digest).await? else {
            return Ok(None);
        };
        if start > end_inclusive || end_inclusive >= metadata.size {
            return Err(
                PlatformError::invalid("invalid blob byte range").with_detail(format!(
                    "digest={} start={start} end={end_inclusive} size={}",
                    metadata.digest, metadata.size
                )),
            );
        }

        let length = end_inclusive
            .checked_sub(start)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| PlatformError::unavailable("blob range length overflowed"))?;
        let path = self.path_for_digest(&metadata.digest)?;
        self.stream_blob_bytes(&path, &metadata.digest, start, length, writer)
            .await?;
        Ok(Some(metadata))
    }

    /// Return the durable reference state for one blob when any physical blob or accounting file exists.
    pub async fn reference_state(&self, digest: &str) -> Result<Option<BlobReferenceState>> {
        let digest = canonicalize_digest(digest)?;
        let metadata = self.metadata(&digest).await?;
        let _guard = self.accounting_guard.lock().await;
        match metadata {
            Some(metadata) => self
                .load_or_initialize_reference_state_locked(&metadata, BlobLineage::direct())
                .await
                .map(Some),
            None => read_reference_state(&self.root, &digest).await,
        }
    }

    /// Add or refresh one durable reference retaining a blob.
    pub async fn add_reference(
        &self,
        digest: &str,
        reference_id: &str,
        kind: BlobReferenceKind,
    ) -> Result<BlobReferenceState> {
        let digest = canonicalize_digest(digest)?;
        let reference_id = normalize_blob_reference_id(reference_id)?;
        let metadata = self
            .metadata(&digest)
            .await?
            .ok_or_else(|| PlatformError::not_found("blob does not exist"))?;
        let _guard = self.accounting_guard.lock().await;
        let mut state = self
            .load_or_initialize_reference_state_locked(&metadata, BlobLineage::direct())
            .await?;
        let now = OffsetDateTime::now_utc();
        state.remember_kind(kind);
        match state.references.get_mut(&reference_id) {
            Some(existing) => {
                existing.kind = kind;
                existing.updated_at = now;
            }
            None => {
                state.references.insert(
                    reference_id,
                    BlobReferenceEntry {
                        kind,
                        created_at: now,
                        updated_at: now,
                    },
                );
            }
        }
        write_reference_state(&self.root, &state).await?;
        Ok(state)
    }

    /// Remove one durable reference retaining a blob.
    pub async fn remove_reference(
        &self,
        digest: &str,
        reference_id: &str,
    ) -> Result<Option<BlobReferenceState>> {
        let digest = canonicalize_digest(digest)?;
        let reference_id = normalize_blob_reference_id(reference_id)?;
        let metadata = self.metadata(&digest).await?;
        let _guard = self.accounting_guard.lock().await;
        let mut state = match (&metadata, read_reference_state(&self.root, &digest).await?) {
            (Some(metadata), Some(mut state)) => {
                state.metadata = metadata.clone();
                state
            }
            (Some(metadata), None) => BlobReferenceState::new(metadata, BlobLineage::direct()),
            (None, Some(state)) => state,
            (None, None) => return Ok(None),
        };

        state.references.remove(&reference_id);
        if metadata.is_none() && state.references.is_empty() {
            delete_reference_state(&self.root, &digest).await?;
            return Ok(None);
        }

        if let Some(metadata) = metadata {
            state.metadata = metadata;
        }
        if !state.should_persist() {
            delete_reference_state(&self.root, &digest).await?;
            return Ok(None);
        }
        write_reference_state(&self.root, &state).await?;
        Ok(Some(state))
    }

    /// Persist one orphan-GC workflow for currently unreferenced multipart or composed blobs.
    pub async fn plan_orphan_garbage_collection(&self) -> Result<Option<BlobGcWorkflow>> {
        let _guard = self.accounting_guard.lock().await;
        let mut digests = self
            .list_digests()
            .await?
            .into_iter()
            .collect::<BTreeSet<_>>();
        digests.extend(list_reference_state_digests(&self.root).await?);

        let mut candidates = Vec::new();
        for digest in digests {
            let Some(metadata) = self.metadata(&digest).await? else {
                delete_reference_state(&self.root, &digest).await?;
                continue;
            };
            let state = self
                .load_or_initialize_reference_state_locked(&metadata, BlobLineage::direct())
                .await?;
            let Some(reason) = state.orphan_reason() else {
                continue;
            };
            candidates.push(BlobGcCandidate {
                digest: metadata.digest.clone(),
                size: metadata.size,
                lineage: state.lineage.clone(),
                reason: String::from(reason),
            });
        }
        if candidates.is_empty() {
            return Ok(None);
        }

        let workflow = BlobGcWorkflow::new(candidates);
        write_gc_workflow(&self.root, &workflow).await?;
        Ok(Some(workflow))
    }

    /// Execute one previously persisted orphan-GC workflow idempotently.
    pub async fn execute_orphan_garbage_collection(
        &self,
        workflow_id: &str,
    ) -> Result<BlobGcWorkflow> {
        let workflow_id = normalize_blob_control_id(workflow_id)?;
        let _guard = self.accounting_guard.lock().await;
        let Some(mut workflow) = read_gc_workflow(&self.root, &workflow_id).await? else {
            return Err(PlatformError::not_found("blob gc workflow does not exist"));
        };
        if matches!(workflow.phase, BlobGcWorkflowPhase::Completed) {
            return Ok(workflow);
        }

        workflow.deleted_digests.clear();
        workflow.skipped_digests.clear();
        for candidate in workflow.candidates.clone() {
            let Some(metadata) = self.metadata(&candidate.digest).await? else {
                delete_reference_state(&self.root, &candidate.digest).await?;
                workflow.skipped_digests.push(candidate.digest);
                continue;
            };
            let state = self
                .load_or_initialize_reference_state_locked(&metadata, BlobLineage::direct())
                .await?;
            if state.orphan_reason().is_none() {
                workflow.skipped_digests.push(candidate.digest);
                continue;
            }

            self.delete_blob_assets_locked(&metadata.digest, Some(OffsetDateTime::now_utc()))
                .await?;
            workflow.deleted_digests.push(metadata.digest);
        }

        workflow.phase = BlobGcWorkflowPhase::Completed;
        workflow.completed_at = Some(OffsetDateTime::now_utc());
        write_gc_workflow(&self.root, &workflow).await?;
        Ok(workflow)
    }

    /// Plan and immediately execute one orphan-GC workflow when candidates exist.
    pub async fn run_orphan_garbage_collection(&self) -> Result<Option<BlobGcWorkflow>> {
        let Some(workflow) = self.plan_orphan_garbage_collection().await? else {
            return Ok(None);
        };
        self.execute_orphan_garbage_collection(&workflow.id)
            .await
            .map(Some)
    }

    /// List the digests currently materialized in the blob store.
    pub async fn list_digests(&self) -> Result<Vec<String>> {
        let mut shard_entries = fs::read_dir(&self.root).await.map_err(|error| {
            PlatformError::unavailable("failed to read blob store root")
                .with_detail(error.to_string())
        })?;
        let mut digests = Vec::new();
        while let Some(shard_entry) = shard_entries.next_entry().await.map_err(|error| {
            PlatformError::unavailable("failed to enumerate blob store root")
                .with_detail(error.to_string())
        })? {
            let path = shard_entry.path();
            let metadata = shard_entry.metadata().await.map_err(|error| {
                PlatformError::unavailable("failed to stat blob shard entry")
                    .with_detail(error.to_string())
            })?;
            if !metadata.is_dir() {
                continue;
            }
            let Some(shard_name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if shard_name == "tmp"
                || shard_name == "gc"
                || shard_name == "refs"
                || shard_name.len() != 2
            {
                continue;
            }

            let mut blob_entries = fs::read_dir(&path).await.map_err(|error| {
                PlatformError::unavailable("failed to read blob shard directory")
                    .with_detail(error.to_string())
            })?;
            while let Some(blob_entry) = blob_entries.next_entry().await.map_err(|error| {
                PlatformError::unavailable("failed to enumerate blob shard directory")
                    .with_detail(error.to_string())
            })? {
                let blob_path = blob_entry.path();
                let blob_metadata = blob_entry.metadata().await.map_err(|error| {
                    PlatformError::unavailable("failed to stat blob shard entry")
                        .with_detail(error.to_string())
                })?;
                if !blob_metadata.is_file() {
                    continue;
                }
                let Some(name) = blob_path.file_name().and_then(|value| value.to_str()) else {
                    continue;
                };
                if name.ends_with(".integrity.json") {
                    continue;
                }
                if let Ok(digest) = canonicalize_digest(name) {
                    digests.push(digest);
                }
            }
        }
        digests.sort();
        Ok(digests)
    }

    /// Delete a stored blob if it exists.
    pub async fn delete(&self, digest: &str) -> Result<()> {
        let digest = canonicalize_digest(digest)?;
        let _guard = self.accounting_guard.lock().await;
        if let Some(state) = read_reference_state(&self.root, &digest).await?
            && !state.references.is_empty()
        {
            return Err(
                PlatformError::conflict("blob has active durable references").with_detail(format!(
                    "digest={} active_references={}",
                    digest,
                    state
                        .references
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(",")
                )),
            );
        }
        self.delete_blob_assets_locked(&digest, None).await
    }

    /// Concatenate existing blobs (by digest) into a new blob without loading all parts in memory.
    ///
    /// The resulting digest is computed while streaming into a temp file, then moved into place.
    /// This keeps multipart completion bounded by the stream buffer rather than the assembled
    /// object size.
    pub async fn concat(&self, digests: &[String]) -> Result<BlobMetadata> {
        self.concat_with_status(digests)
            .await
            .map(|outcome| outcome.metadata)
    }

    /// Concatenate existing blobs and report whether a new canonical blob was published.
    pub async fn concat_with_status(&self, digests: &[String]) -> Result<BlobWriteOutcome> {
        if digests.is_empty() {
            return Err(PlatformError::invalid("no parts provided for concat"));
        }

        // A unique temp file prevents readers from observing a partially written blob
        // before the final digest is known.
        let temp_path = unique_temp_path(&self.root, "concat");
        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(parent).await.map_err(|error| {
                PlatformError::unavailable("failed to create blob temp directory")
                    .with_detail(error.to_string())
            })?;
        }
        let mut temp_file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .await
            .map_err(|error| {
                PlatformError::unavailable("failed to create temp blob file")
                    .with_detail(error.to_string())
            })?;

        let result = async {
            let mut hasher = Sha256::new();
            let mut total_size: u64 = 0;
            let mut buffer = [0_u8; BLOB_STREAM_CHUNK_SIZE];

            for digest in digests {
                let part_metadata = self.metadata(digest).await?.ok_or_else(|| {
                    PlatformError::not_found("blob part does not exist")
                        .with_detail(format!("digest={digest}"))
                })?;
                let path = self.path_for_digest(&part_metadata.digest)?;
                let mut part = File::open(&path).await.map_err(|error| {
                    if error.kind() == std::io::ErrorKind::NotFound {
                        PlatformError::not_found("blob part does not exist")
                            .with_detail(format!("digest={}", part_metadata.digest))
                    } else {
                        PlatformError::unavailable("failed to open blob part")
                            .with_detail(error.to_string())
                    }
                })?;
                let mut remaining_part_bytes = part_metadata.size;
                while remaining_part_bytes > 0 {
                    let next_read =
                        remaining_part_bytes.min(BLOB_STREAM_CHUNK_SIZE as u64) as usize;
                    let read = part.read(&mut buffer[..next_read]).await.map_err(|error| {
                        PlatformError::unavailable("failed to read blob part")
                            .with_detail(error.to_string())
                    })?;
                    if read == 0 {
                        return Err(PlatformError::unavailable(
                            "blob part truncated during concat",
                        )
                        .with_detail(format!(
                            "digest={} remaining_bytes={remaining_part_bytes}",
                            part_metadata.digest
                        )));
                    }
                    hasher.update(&buffer[..read]);
                    temp_file
                        .write_all(&buffer[..read])
                        .await
                        .map_err(|error| {
                            PlatformError::unavailable("failed to write assembled blob")
                                .with_detail(error.to_string())
                        })?;
                    total_size = total_size.checked_add(read as u64).ok_or_else(|| {
                        PlatformError::unavailable("assembled blob size overflowed")
                    })?;
                    remaining_part_bytes = remaining_part_bytes
                        .checked_sub(read as u64)
                        .ok_or_else(|| {
                            PlatformError::unavailable("assembled blob size underflowed")
                        })?;
                }
            }

            temp_file.flush().await.map_err(|error| {
                PlatformError::unavailable("failed to flush assembled blob")
                    .with_detail(error.to_string())
            })?;
            temp_file.sync_all().await.map_err(|error| {
                PlatformError::unavailable("failed to sync assembled blob")
                    .with_detail(error.to_string())
            })?;
            drop(temp_file);

            let digest_bytes = hasher.finalize();
            let digest = hex_digest(digest_bytes);
            let final_path = self.path_for_digest(&digest)?;
            if let Some(parent) = final_path.parent() {
                fs::create_dir_all(parent).await.map_err(|error| {
                    PlatformError::unavailable("failed to create blob shard directory")
                        .with_detail(error.to_string())
                })?;
            }

            let metadata = BlobMetadata {
                digest: digest.clone(),
                size: total_size,
            };
            let published = {
                let _guard = self.accounting_guard.lock().await;

                match fs::metadata(&final_path).await {
                    Ok(existing) => {
                        let _ = fs::remove_file(&temp_path).await;
                        let metadata = BlobMetadata {
                            digest: digest.clone(),
                            size: existing.len(),
                        };
                        self.sync_reference_state_locked(&metadata, BlobLineage::composed(digests))
                            .await?;
                        (metadata, false)
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        // Persist composed lineage before the final rename so publish
                        // crashes do not lose orphan-GC accounting.
                        self.sync_reference_state_locked(&metadata, BlobLineage::composed(digests))
                            .await?;
                        if let Err(error) = fs::rename(&temp_path, &final_path).await {
                            if let Ok(existing) = fs::metadata(&final_path).await {
                                let _ = fs::remove_file(&temp_path).await;
                                let metadata = BlobMetadata {
                                    digest: digest.clone(),
                                    size: existing.len(),
                                };
                                self.sync_reference_state_locked(
                                    &metadata,
                                    BlobLineage::composed(digests),
                                )
                                .await?;
                                (metadata, false)
                            } else {
                                delete_reference_state(&self.root, &metadata.digest).await?;
                                return Err(PlatformError::unavailable(
                                    "failed to persist assembled blob",
                                )
                                .with_detail(error.to_string()));
                            }
                        } else {
                            sync_path_parent(&final_path).await?;
                            (metadata, true)
                        }
                    }
                    Err(error) => {
                        return Err(PlatformError::unavailable(
                            "failed to stat composed blob target",
                        )
                        .with_detail(error.to_string()));
                    }
                }
            };

            self.ensure_integrity_sidecar(&final_path, &published.0)
                .await?;
            Ok(BlobWriteOutcome {
                metadata: published.0,
                created_new: published.1,
            })
        }
        .await;

        if result.is_err() {
            let _ = fs::remove_file(&temp_path).await;
        }
        result
    }

    async fn sync_reference_state(
        &self,
        metadata: &BlobMetadata,
        lineage: BlobLineage,
    ) -> Result<BlobReferenceState> {
        let _guard = self.accounting_guard.lock().await;
        self.sync_reference_state_locked(metadata, lineage).await
    }

    async fn sync_reference_state_locked(
        &self,
        metadata: &BlobMetadata,
        lineage: BlobLineage,
    ) -> Result<BlobReferenceState> {
        let state = self
            .load_or_initialize_reference_state_locked(metadata, lineage)
            .await?;
        write_reference_state(&self.root, &state).await?;
        Ok(state)
    }

    async fn load_or_initialize_reference_state_locked(
        &self,
        metadata: &BlobMetadata,
        lineage: BlobLineage,
    ) -> Result<BlobReferenceState> {
        let mut state = read_reference_state(&self.root, &metadata.digest)
            .await?
            .unwrap_or_else(|| BlobReferenceState::new(metadata, lineage.clone()));
        state.metadata = metadata.clone();
        state.merge_lineage(lineage);
        state.last_collected_at = None;
        Ok(state)
    }

    async fn delete_blob_assets_locked(
        &self,
        digest: &str,
        collected_at: Option<OffsetDateTime>,
    ) -> Result<()> {
        let path = self.path_for_digest(digest)?;
        let sidecar_path = integrity_sidecar_path(&path);
        let reference_path = reference_state_path(&self.root, digest)?;

        let blob_deleted = remove_file_if_exists(&path, "blob").await?;
        let sidecar_deleted =
            remove_file_if_exists(&sidecar_path, "blob integrity sidecar").await?;
        let reference_deleted = match collected_at {
            Some(collected_at) => {
                if let Some(mut state) = read_reference_state(&self.root, digest).await? {
                    state.last_collected_at = Some(collected_at);
                    write_reference_state(&self.root, &state).await?;
                }
                remove_file_if_exists(&reference_path, "blob reference state").await?
            }
            None => remove_file_if_exists(&reference_path, "blob reference state").await?,
        };

        if (blob_deleted || sidecar_deleted)
            && let Some(parent) = path.parent()
        {
            sync_directory(parent).await?;
        }
        if reference_deleted && let Some(parent) = reference_path.parent() {
            sync_directory(parent).await?;
        }
        Ok(())
    }

    async fn ensure_integrity_sidecar(&self, path: &Path, metadata: &BlobMetadata) -> Result<()> {
        match read_integrity_sidecar(path).await? {
            Some(sidecar) => sidecar.validate(metadata),
            None => self.write_integrity_sidecar(path, metadata).await,
        }
    }

    async fn write_integrity_sidecar(&self, path: &Path, metadata: &BlobMetadata) -> Result<()> {
        let sidecar_payload = serde_json::to_vec(&BlobIntegritySidecar::from_metadata(metadata))
            .map_err(|error| {
                PlatformError::unavailable("failed to encode blob integrity sidecar")
                    .with_detail(error.to_string())
            })?;
        let sidecar_path = integrity_sidecar_path(path);
        let temp_path = unique_temp_path(&self.root, "integrity");
        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(parent).await.map_err(|error| {
                PlatformError::unavailable("failed to create blob temp directory")
                    .with_detail(error.to_string())
            })?;
        }

        let result = async {
            let mut temp_file = tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp_path)
                .await
                .map_err(|error| {
                    PlatformError::unavailable("failed to create blob integrity temp file")
                        .with_detail(error.to_string())
                })?;
            temp_file
                .write_all(&sidecar_payload)
                .await
                .map_err(|error| {
                    PlatformError::unavailable("failed to persist blob integrity sidecar")
                        .with_detail(error.to_string())
                })?;
            temp_file.flush().await.map_err(|error| {
                PlatformError::unavailable("failed to flush blob integrity sidecar")
                    .with_detail(error.to_string())
            })?;
            temp_file.sync_all().await.map_err(|error| {
                PlatformError::unavailable("failed to sync blob integrity sidecar")
                    .with_detail(error.to_string())
            })?;
            drop(temp_file);

            if let Err(error) = fs::rename(&temp_path, &sidecar_path).await {
                if let Some(existing) = read_integrity_sidecar(path).await? {
                    existing.validate(metadata)?;
                    let _ = fs::remove_file(&temp_path).await;
                    return Ok(());
                }
                return Err(
                    PlatformError::unavailable("failed to persist blob integrity sidecar")
                        .with_detail(error.to_string()),
                );
            }

            if let Some(parent) = sidecar_path.parent() {
                sync_directory(parent).await?;
            }
            Ok(())
        }
        .await;

        if result.is_err() {
            let _ = fs::remove_file(&temp_path).await;
        }
        result
    }

    async fn stream_blob_bytes<W>(
        &self,
        path: &Path,
        digest: &str,
        offset: u64,
        length: u64,
        writer: &mut W,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        if length == 0 {
            writer.flush().await.map_err(|error| {
                PlatformError::unavailable("failed to flush streamed blob")
                    .with_detail(error.to_string())
            })?;
            return Ok(());
        }

        let mut file = self.open_blob_file(path, offset).await?;
        let mut remaining = length;
        let mut buffer = [0_u8; BLOB_STREAM_CHUNK_SIZE];
        while remaining > 0 {
            let next_read = remaining.min(BLOB_STREAM_CHUNK_SIZE as u64) as usize;
            let read = file.read(&mut buffer[..next_read]).await.map_err(|error| {
                PlatformError::unavailable("failed to read blob").with_detail(error.to_string())
            })?;
            if read == 0 {
                return Err(
                    PlatformError::unavailable("blob truncated during read").with_detail(format!(
                        "digest={digest} offset={offset} remaining={remaining}"
                    )),
                );
            }
            writer.write_all(&buffer[..read]).await.map_err(|error| {
                PlatformError::unavailable("failed to stream blob").with_detail(error.to_string())
            })?;
            remaining = remaining
                .checked_sub(read as u64)
                .ok_or_else(|| PlatformError::unavailable("blob stream length underflowed"))?;
        }
        writer.flush().await.map_err(|error| {
            PlatformError::unavailable("failed to flush streamed blob")
                .with_detail(error.to_string())
        })
    }

    async fn read_blob_bytes(
        &self,
        path: &Path,
        digest: &str,
        offset: u64,
        length: u64,
    ) -> Result<Bytes> {
        if length == 0 {
            return Ok(Bytes::new());
        }
        let capacity = usize::try_from(length).map_err(|_| {
            PlatformError::unavailable("blob read exceeds platform memory address space")
                .with_detail(format!("digest={digest} length={length}"))
        })?;

        let mut file = self.open_blob_file(path, offset).await?;
        let mut remaining = length;
        let mut output = Vec::with_capacity(capacity);
        let mut buffer = [0_u8; BLOB_STREAM_CHUNK_SIZE];
        while remaining > 0 {
            let next_read = remaining.min(BLOB_STREAM_CHUNK_SIZE as u64) as usize;
            let read = file.read(&mut buffer[..next_read]).await.map_err(|error| {
                PlatformError::unavailable("failed to read blob").with_detail(error.to_string())
            })?;
            if read == 0 {
                return Err(
                    PlatformError::unavailable("blob truncated during read").with_detail(format!(
                        "digest={digest} offset={offset} remaining={remaining}"
                    )),
                );
            }
            output.extend_from_slice(&buffer[..read]);
            remaining = remaining
                .checked_sub(read as u64)
                .ok_or_else(|| PlatformError::unavailable("blob read length underflowed"))?;
        }
        Ok(Bytes::from(output))
    }

    async fn open_blob_file(&self, path: &Path, offset: u64) -> Result<File> {
        let mut file = File::open(path).await.map_err(|error| {
            PlatformError::unavailable("failed to open blob").with_detail(error.to_string())
        })?;
        file.seek(SeekFrom::Start(offset)).await.map_err(|error| {
            PlatformError::unavailable("failed to seek blob").with_detail(error.to_string())
        })?;
        Ok(file)
    }

    fn path_for_digest(&self, digest: &str) -> Result<PathBuf> {
        let digest = canonicalize_digest(digest)?;
        let prefix = &digest[..2];
        Ok(self.root.join(prefix).join(digest))
    }
}

fn canonicalize_digest(digest: &str) -> Result<String> {
    if digest.len() != 64
        || !digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(PlatformError::invalid(
            "blob digest must be 64 hex characters",
        ));
    }

    Ok(digest.to_ascii_lowercase())
}

fn normalize_blob_reference_id(reference_id: &str) -> Result<String> {
    let trimmed = reference_id.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return Err(PlatformError::invalid(
            "blob reference id must be between 1 and 256 characters",
        ));
    }
    if !trimmed.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | ':' | '.' | '/')
    }) {
        return Err(PlatformError::invalid(
            "blob reference id contains unsupported characters",
        ));
    }
    Ok(trimmed.to_owned())
}

fn normalize_blob_control_id(id: &str) -> Result<String> {
    let trimmed = id.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return Err(PlatformError::invalid(
            "blob control id must be between 1 and 256 characters",
        ));
    }
    if !trimmed
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(PlatformError::invalid(
            "blob control id contains unsupported characters",
        ));
    }
    Ok(trimmed.to_owned())
}

fn shared_blob_accounting_guard(root: &Path) -> Arc<Mutex<()>> {
    static REGISTRY: OnceLock<StdMutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();

    let registry = REGISTRY.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut registry = registry.lock().unwrap_or_else(|poison| poison.into_inner());
    registry
        .entry(root.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

fn references_root(root: &Path) -> PathBuf {
    root.join("refs")
}

fn reference_state_path(root: &Path, digest: &str) -> Result<PathBuf> {
    let digest = canonicalize_digest(digest)?;
    Ok(references_root(root)
        .join(&digest[..2])
        .join(format!("{digest}.refs.json")))
}

fn gc_workflows_root(root: &Path) -> PathBuf {
    root.join("gc").join("workflows")
}

fn gc_workflow_path(root: &Path, workflow_id: &str) -> Result<PathBuf> {
    let workflow_id = normalize_blob_control_id(workflow_id)?;
    Ok(gc_workflows_root(root).join(format!("{workflow_id}.json")))
}

fn next_blob_gc_workflow_id() -> String {
    static COUNTER: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();

    let counter = COUNTER.get_or_init(|| std::sync::atomic::AtomicU64::new(0));
    let suffix = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!(
        "bgc-{}-{suffix}",
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    )
}

async fn read_reference_state(root: &Path, digest: &str) -> Result<Option<BlobReferenceState>> {
    let path = reference_state_path(root, digest)?;
    match fs::read(&path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|error| {
            PlatformError::unavailable("failed to decode blob reference state")
                .with_detail(error.to_string())
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(
            PlatformError::unavailable("failed to read blob reference state")
                .with_detail(error.to_string()),
        ),
    }
}

async fn write_reference_state(root: &Path, state: &BlobReferenceState) -> Result<()> {
    let payload = serde_json::to_vec(state).map_err(|error| {
        PlatformError::unavailable("failed to encode blob reference state")
            .with_detail(error.to_string())
    })?;
    let path = reference_state_path(root, &state.metadata.digest)?;
    write_json_atomically(root, &path, "blob-ref", &payload).await
}

async fn delete_reference_state(root: &Path, digest: &str) -> Result<()> {
    let path = reference_state_path(root, digest)?;
    if remove_file_if_exists(&path, "blob reference state").await?
        && let Some(parent) = path.parent()
    {
        sync_directory(parent).await?;
    }
    Ok(())
}

async fn list_reference_state_digests(root: &Path) -> Result<Vec<String>> {
    let refs_root = references_root(root);
    let mut shard_entries = match fs::read_dir(&refs_root).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(
                PlatformError::unavailable("failed to read blob reference root")
                    .with_detail(error.to_string()),
            );
        }
    };
    let mut digests = BTreeSet::new();
    while let Some(shard_entry) = shard_entries.next_entry().await.map_err(|error| {
        PlatformError::unavailable("failed to enumerate blob reference root")
            .with_detail(error.to_string())
    })? {
        let metadata = shard_entry.metadata().await.map_err(|error| {
            PlatformError::unavailable("failed to stat blob reference shard")
                .with_detail(error.to_string())
        })?;
        if !metadata.is_dir() {
            continue;
        }

        let mut ref_entries = fs::read_dir(shard_entry.path()).await.map_err(|error| {
            PlatformError::unavailable("failed to read blob reference shard")
                .with_detail(error.to_string())
        })?;
        while let Some(entry) = ref_entries.next_entry().await.map_err(|error| {
            PlatformError::unavailable("failed to enumerate blob reference shard")
                .with_detail(error.to_string())
        })? {
            let entry_metadata = entry.metadata().await.map_err(|error| {
                PlatformError::unavailable("failed to stat blob reference entry")
                    .with_detail(error.to_string())
            })?;
            if !entry_metadata.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            let Some(digest) = name.strip_suffix(".refs.json") else {
                continue;
            };
            if let Ok(digest) = canonicalize_digest(digest) {
                digests.insert(digest);
            }
        }
    }
    Ok(digests.into_iter().collect())
}

async fn read_gc_workflow(root: &Path, workflow_id: &str) -> Result<Option<BlobGcWorkflow>> {
    let path = gc_workflow_path(root, workflow_id)?;
    match fs::read(&path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|error| {
            PlatformError::unavailable("failed to decode blob gc workflow")
                .with_detail(error.to_string())
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(
            PlatformError::unavailable("failed to read blob gc workflow")
                .with_detail(error.to_string()),
        ),
    }
}

async fn write_gc_workflow(root: &Path, workflow: &BlobGcWorkflow) -> Result<()> {
    let payload = serde_json::to_vec(workflow).map_err(|error| {
        PlatformError::unavailable("failed to encode blob gc workflow")
            .with_detail(error.to_string())
    })?;
    let path = gc_workflow_path(root, &workflow.id)?;
    write_json_atomically(root, &path, "blob-gc", &payload).await
}

async fn read_integrity_sidecar(path: &Path) -> Result<Option<BlobIntegritySidecar>> {
    let sidecar_path = integrity_sidecar_path(path);
    match fs::read(&sidecar_path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|error| {
            PlatformError::unavailable("failed to decode blob integrity sidecar")
                .with_detail(error.to_string())
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(
            PlatformError::unavailable("failed to read blob integrity sidecar")
                .with_detail(error.to_string()),
        ),
    }
}

fn integrity_sidecar_path(path: &Path) -> PathBuf {
    path.with_extension("integrity.json")
}

async fn sync_path_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        sync_directory(parent).await?;
    }
    Ok(())
}

#[cfg(windows)]
async fn sync_directory(_path: &Path) -> Result<()> {
    // Tokio cannot reopen directories on Windows the same way Unix can for a
    // durable parent-directory fsync, so keep this best-effort there.
    Ok(())
}

#[cfg(not(windows))]
async fn sync_directory(path: &Path) -> Result<()> {
    let directory = File::open(path).await.map_err(|error| {
        PlatformError::unavailable("failed to open blob parent directory")
            .with_detail(error.to_string())
    })?;
    directory.sync_all().await.map_err(|error| {
        PlatformError::unavailable("failed to sync blob parent directory")
            .with_detail(error.to_string())
    })
}

async fn remove_file_if_exists(path: &Path, description: &str) -> Result<bool> {
    match fs::remove_file(path).await {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(
            PlatformError::unavailable(format!("failed to delete {description}"))
                .with_detail(format!("path={} error={error}", path.display())),
        ),
    }
}

async fn write_json_atomically(
    root: &Path,
    path: &Path,
    prefix: &str,
    payload: &[u8],
) -> Result<()> {
    let temp_path = unique_temp_path(root, prefix);
    if let Some(parent) = temp_path.parent() {
        fs::create_dir_all(parent).await.map_err(|error| {
            PlatformError::unavailable("failed to create blob temp directory")
                .with_detail(error.to_string())
        })?;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await.map_err(|error| {
            PlatformError::unavailable("failed to create blob control directory")
                .with_detail(error.to_string())
        })?;
    }

    let result = async {
        let mut temp_file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .await
            .map_err(|error| {
                PlatformError::unavailable("failed to create blob control temp file")
                    .with_detail(error.to_string())
            })?;
        temp_file.write_all(payload).await.map_err(|error| {
            PlatformError::unavailable("failed to persist blob control file")
                .with_detail(error.to_string())
        })?;
        temp_file.flush().await.map_err(|error| {
            PlatformError::unavailable("failed to flush blob control temp file")
                .with_detail(error.to_string())
        })?;
        temp_file.sync_all().await.map_err(|error| {
            PlatformError::unavailable("failed to sync blob control temp file")
                .with_detail(error.to_string())
        })?;
        drop(temp_file);

        fs::rename(&temp_path, path).await.map_err(|error| {
            PlatformError::unavailable("failed to persist blob control file")
                .with_detail(error.to_string())
        })?;
        if let Some(parent) = path.parent() {
            sync_directory(parent).await?;
        }
        Ok(())
    }
    .await;

    if result.is_err() {
        let _ = fs::remove_file(&temp_path).await;
    }
    result
}

fn unique_temp_path(root: &Path, prefix: &str) -> PathBuf {
    static COUNTER: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();

    let counter = COUNTER.get_or_init(|| std::sync::atomic::AtomicU64::new(0));
    let suffix = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    root.join("tmp")
        .join(format!("{prefix}-{}.{}.tmp", std::process::id(), suffix))
}

fn hex_digest(digest: impl AsRef<[u8]>) -> String {
    let digest = digest.as_ref();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = core::fmt::Write::write_fmt(&mut output, format_args!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use bytes::Bytes;
    use serde_json::json;
    use tempfile::tempdir;
    use tokio::fs;

    use super::{
        BLOB_STREAM_CHUNK_SIZE, BlobGcWorkflowPhase, BlobLineageKind, BlobReferenceKind, BlobStore,
        integrity_sidecar_path, reference_state_path,
    };

    #[derive(Debug, Default)]
    struct RecordingWriter {
        bytes: Vec<u8>,
        write_sizes: Vec<usize>,
        flush_count: usize,
    }

    impl tokio::io::AsyncWrite for RecordingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.write_sizes.push(buf.len());
            self.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.flush_count += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn store_and_load_blob() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let meta = store
            .put(Bytes::from_static(b"hello"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let loaded = store
            .get(&meta.digest)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing blob"));
        assert_eq!(&loaded[..], b"hello");

        let sidecar_path = integrity_sidecar_path(
            &store
                .path_for_digest(&meta.digest)
                .unwrap_or_else(|error| panic!("{error}")),
        );
        assert!(
            fs::metadata(&sidecar_path).await.is_ok(),
            "integrity sidecar should exist after write"
        );

        store
            .delete(&meta.digest)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let missing = store
            .get(&meta.digest)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(missing.is_none(), "deleted blob should be gone");
        assert!(
            matches!(
                fs::metadata(&sidecar_path).await,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ),
            "integrity sidecar should be removed with the blob"
        );
    }

    #[tokio::test]
    async fn rejects_non_canonical_digest_paths() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = store
            .get("../escape")
            .await
            .expect_err("expected invalid digest to fail");
        assert!(error.to_string().contains("blob digest"));
    }

    #[tokio::test]
    async fn concat_streams_parts_and_preserves_digest() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first = store
            .put(Bytes::from_static(b"hello "))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second = store
            .put(Bytes::from_static(b"world"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let digests = [first.digest.clone(), second.digest.clone()];
        let combined = store
            .concat(&digests)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let loaded = store
            .get(&combined.digest)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing concatenated blob"));
        assert_eq!(loaded.as_ref(), b"hello world");
        assert_eq!(combined.size, 11);
    }

    #[tokio::test]
    async fn put_writes_integrity_sidecar_and_supports_range_reads() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let metadata = store
            .put(Bytes::from_static(b"hello world"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let sidecar_path = integrity_sidecar_path(
            &store
                .path_for_digest(&metadata.digest)
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let sidecar = fs::read_to_string(&sidecar_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload: serde_json::Value =
            serde_json::from_str(&sidecar).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(payload["algorithm"], json!("sha256"));
        assert_eq!(payload["digest"], json!(metadata.digest));
        assert_eq!(payload["size"], json!(11));

        let range = store
            .get_range(metadata.digest.as_str(), 6, 10)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing range"));
        assert_eq!(range.as_ref(), b"world");
    }

    #[tokio::test]
    async fn stream_range_to_writes_large_ranges_in_chunks() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let payload = (0..(BLOB_STREAM_CHUNK_SIZE * 2 + 97))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let metadata = store
            .put(Bytes::from(payload.clone()))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let start = 13_u64;
        let end_inclusive = (payload.len() - 15) as u64;
        let mut writer = RecordingWriter::default();
        let streamed = store
            .stream_range_to(metadata.digest.as_str(), start, end_inclusive, &mut writer)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing streamed blob"));

        assert_eq!(streamed, metadata);
        assert_eq!(
            writer.bytes,
            payload[start as usize..=end_inclusive as usize].to_vec()
        );
        assert!(
            writer.write_sizes.len() > 1,
            "large ranges should be emitted over multiple writes"
        );
        assert!(
            writer
                .write_sizes
                .iter()
                .all(|size| *size <= BLOB_STREAM_CHUNK_SIZE)
        );
        assert!(
            writer.flush_count >= 1,
            "streamed writes should flush the sink"
        );
    }

    #[tokio::test]
    async fn stream_to_recreates_missing_integrity_sidecar() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let payload = Bytes::from_static(b"stream me");
        let metadata = store
            .put(payload.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let sidecar_path = integrity_sidecar_path(
            &store
                .path_for_digest(&metadata.digest)
                .unwrap_or_else(|error| panic!("{error}")),
        );
        fs::remove_file(&sidecar_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            matches!(
                fs::metadata(&sidecar_path).await,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ),
            "test setup should remove the integrity sidecar"
        );

        let mut writer = RecordingWriter::default();
        let streamed = store
            .stream_to(metadata.digest.as_str(), &mut writer)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing streamed blob"));
        assert_eq!(streamed, metadata);
        assert_eq!(writer.bytes, payload);
        assert!(
            fs::metadata(&sidecar_path).await.is_ok(),
            "streamed reads should restore missing integrity sidecars"
        );
    }

    #[tokio::test]
    async fn metadata_rejects_integrity_sidecar_mismatch() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let metadata = store
            .put(Bytes::from_static(b"hello"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let sidecar_path = integrity_sidecar_path(
            &store
                .path_for_digest(&metadata.digest)
                .unwrap_or_else(|error| panic!("{error}")),
        );
        fs::write(
            &sidecar_path,
            serde_json::to_vec(&json!({
                "algorithm": "sha256",
                "digest": metadata.digest,
                "size": 99,
            }))
            .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let error = store
            .metadata(metadata.digest.as_str())
            .await
            .expect_err("mismatched sidecar should fail");
        assert!(
            error
                .to_string()
                .contains("blob integrity sidecar mismatch")
        );
    }

    #[tokio::test]
    async fn concat_rejects_part_with_integrity_sidecar_mismatch() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first = store
            .put(Bytes::from_static(b"hello "))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second = store
            .put(Bytes::from_static(b"world"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_sidecar = integrity_sidecar_path(
            &store
                .path_for_digest(&first.digest)
                .unwrap_or_else(|error| panic!("{error}")),
        );
        fs::write(
            &first_sidecar,
            serde_json::to_vec(&json!({
                "algorithm": "sha256",
                "digest": first.digest,
                "size": 999,
            }))
            .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let error = store
            .concat(&[first.digest, second.digest])
            .await
            .expect_err("concat should validate part integrity sidecars");
        assert!(
            error
                .to_string()
                .contains("blob integrity sidecar mismatch")
        );
    }

    #[tokio::test]
    async fn multipart_reference_accounting_and_gc_workflow_survive_reopen() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let blob = store
            .put(Bytes::from_static(b"multipart-part"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = store
            .add_reference(
                blob.digest.as_str(),
                "upload:upl_1:part:1",
                BlobReferenceKind::MultipartUpload,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        drop(store);

        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let state = store
            .reference_state(blob.digest.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing blob reference state"));
        assert_eq!(state.references.len(), 1);
        assert_eq!(
            state
                .references
                .get("upload:upl_1:part:1")
                .unwrap_or_else(|| panic!("missing multipart reference"))
                .kind,
            BlobReferenceKind::MultipartUpload
        );

        let _ = store
            .remove_reference(blob.digest.as_str(), "upload:upl_1:part:1")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow = store
            .plan_orphan_garbage_collection()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing blob gc workflow"));
        assert!(
            workflow
                .candidates
                .iter()
                .any(|candidate| candidate.digest == blob.digest
                    && candidate.reason.contains("multipart"))
        );
        let workflow_id = workflow.id.clone();
        drop(store);

        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow = store
            .execute_orphan_garbage_collection(&workflow_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(workflow.phase, BlobGcWorkflowPhase::Completed);
        assert_eq!(workflow.deleted_digests, vec![blob.digest.clone()]);
        let missing = store
            .get(blob.digest.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            missing.is_none(),
            "orphaned multipart part should be deleted"
        );
    }

    #[tokio::test]
    async fn composed_blob_gc_waits_for_root_reference_then_collects_after_release() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first = store
            .put(Bytes::from_static(b"hello "))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second = store
            .put(Bytes::from_static(b"world"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let digests = vec![first.digest.clone(), second.digest.clone()];
        let combined = store
            .concat(&digests)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let state = store
            .reference_state(combined.digest.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing composed blob reference state"));
        assert_eq!(state.lineage.kind, BlobLineageKind::Composed);
        assert_eq!(state.lineage.source_digests, digests);

        let _ = store
            .add_reference(
                combined.digest.as_str(),
                "upload:upl_1:object",
                BlobReferenceKind::DurableRoot,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            store
                .run_orphan_garbage_collection()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none(),
            "rooted composed object should not be collected"
        );

        let _ = store
            .remove_reference(combined.digest.as_str(), "upload:upl_1:object")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow = store
            .run_orphan_garbage_collection()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("expected composed orphan workflow"));
        assert_eq!(workflow.deleted_digests, vec![combined.digest.clone()]);

        let missing = store
            .get(combined.digest.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            missing.is_none(),
            "released composed object should be deleted"
        );

        let first_part = store
            .get(first.digest.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("direct part should remain"));
        assert_eq!(first_part.as_ref(), b"hello ");
    }

    #[tokio::test]
    async fn removing_last_direct_root_reference_drops_empty_accounting_file() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let blob = store
            .put(Bytes::from_static(b"rooted"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let reference_path = reference_state_path(temp.path(), blob.digest.as_str())
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = store
            .add_reference(
                blob.digest.as_str(),
                "upload:upl_1:object",
                BlobReferenceKind::DurableRoot,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            fs::metadata(&reference_path).await.is_ok(),
            "durable reference should persist an accounting file"
        );

        let state = store
            .remove_reference(blob.digest.as_str(), "upload:upl_1:object")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            state.is_none(),
            "direct blobs with no staging lineage should drop empty accounting"
        );
        assert!(
            matches!(
                fs::metadata(&reference_path).await,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ),
            "empty direct-root accounting file should be cleaned up"
        );
        assert!(
            store
                .plan_orphan_garbage_collection()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none(),
            "released direct roots should not be auto-collected"
        );
    }

    #[tokio::test]
    async fn orphan_gc_workflow_skips_blob_that_regains_reference_before_execution() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let blob = store
            .put(Bytes::from_static(b"multipart-part"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = store
            .add_reference(
                blob.digest.as_str(),
                "upload:upl_1:part:1",
                BlobReferenceKind::MultipartUpload,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = store
            .remove_reference(blob.digest.as_str(), "upload:upl_1:part:1")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow = store
            .plan_orphan_garbage_collection()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing planned gc workflow"));

        let _ = store
            .add_reference(
                blob.digest.as_str(),
                "upload:upl_1:part:1",
                BlobReferenceKind::MultipartUpload,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow = store
            .execute_orphan_garbage_collection(workflow.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(workflow.deleted_digests.is_empty());
        assert_eq!(workflow.skipped_digests, vec![blob.digest.clone()]);
        let loaded = store
            .get(blob.digest.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("blob should remain after re-root"));
        assert_eq!(loaded.as_ref(), b"multipart-part");
    }

    #[tokio::test]
    async fn garbage_collection_hold_blocks_multipart_gc_until_release() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let blob = store
            .put(Bytes::from_static(b"held-part"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = store
            .add_reference(
                blob.digest.as_str(),
                "upload:upl_1:part:1",
                BlobReferenceKind::MultipartUpload,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = store
            .remove_reference(blob.digest.as_str(), "upload:upl_1:part:1")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = store
            .add_reference(
                blob.digest.as_str(),
                "gc:review",
                BlobReferenceKind::GarbageCollectionHold,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(
            store
                .run_orphan_garbage_collection()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none(),
            "active hold should prevent orphan collection"
        );

        let _ = store
            .remove_reference(blob.digest.as_str(), "gc:review")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workflow = store
            .run_orphan_garbage_collection()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("expected gc workflow after hold release"));
        assert_eq!(workflow.deleted_digests, vec![blob.digest.clone()]);
    }

    #[tokio::test]
    async fn delete_rejects_blob_with_active_references() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let blob = store
            .put(Bytes::from_static(b"protected"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = store
            .add_reference(
                blob.digest.as_str(),
                "upload:upl_1:object",
                BlobReferenceKind::DurableRoot,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = store
            .delete(blob.digest.as_str())
            .await
            .expect_err("delete should reject active references");
        assert!(error.to_string().contains("active durable references"));
    }

    #[tokio::test]
    async fn concat_cleans_temp_file_when_part_is_missing() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let store = BlobStore::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = store
            .concat(&[String::from(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )])
            .await
            .expect_err("missing part should fail");
        assert!(error.to_string().contains("blob part does not exist"));

        let temp_dir = temp.path().join("tmp");
        let temp_entries = match fs::read_dir(&temp_dir).await {
            Ok(mut entries) => entries
                .next_entry()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("{error}"),
        };
        assert!(
            temp_entries.is_none(),
            "failed concat should not leak temp files"
        );
    }
}
