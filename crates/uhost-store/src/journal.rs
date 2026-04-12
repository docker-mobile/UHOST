//! Journal-backed local metadata write batches.
//!
//! The local all-in-one store persists each metadata collection as one JSON
//! document file. [`MetadataWriteBatch`] layers a small write-ahead journal over
//! those files so a service can durably commit a primary record, secondary
//! indexes, and an outbox/relay document as one unit. If the process crashes
//! after the journal entry is written but before every target rename completes,
//! reopening the journal replays the remaining file installs.

use std::any::Any;
use std::collections::BTreeMap;
use std::future::Future;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, OwnedMutexGuard};

use uhost_core::{PlatformError, Result, sha256_hex};
use uhost_types::AuditId;

use crate::document::{
    DocumentCollection, DocumentStore, secure_directory_permissions, secure_file_permissions,
    shared_write_guard, sync_parent_dir, unique_temp_path,
};
use crate::metadata::MetadataCollection;

type BatchPrepareFuture = Pin<Box<dyn Future<Output = Result<PreparedWrite>> + Send>>;
type BatchFinalizeFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

trait BatchTarget: Any + Send {
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn prepare(self: Box<Self>) -> BatchPrepareFuture;
}

trait BatchFinalizer: Send + Sync {
    fn finalize(self: Box<Self>) -> BatchFinalizeFuture;
}

struct PreparedWrite {
    target_path: PathBuf,
    payload: Vec<u8>,
    payload_sha256: String,
    finalizer: Box<dyn BatchFinalizer>,
}

impl PreparedWrite {
    async fn finalize(self) -> Result<()> {
        self.finalizer.finalize().await
    }
}

enum DocumentMutation<T> {
    Create {
        key: String,
        value: T,
    },
    Upsert {
        key: String,
        value: T,
        expected_version: Option<u64>,
    },
    SoftDelete {
        key: String,
        expected_version: Option<u64>,
    },
}

struct DocumentTarget<T> {
    store: DocumentStore<T>,
    operations: Vec<DocumentMutation<T>>,
}

impl<T> DocumentTarget<T> {
    fn new(store: DocumentStore<T>, operation: DocumentMutation<T>) -> Self {
        Self {
            store,
            operations: vec![operation],
        }
    }
}

impl<T> BatchTarget for DocumentTarget<T>
where
    T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
{
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn prepare(self: Box<Self>) -> BatchPrepareFuture {
        Box::pin(async move {
            let Self { store, operations } = *self;
            let target_path = store.path().to_path_buf();
            let mut collection = store.snapshot_collection().await?;
            for operation in operations {
                match operation {
                    DocumentMutation::Create { key, value } => {
                        DocumentStore::apply_create_to_collection(&mut collection, &key, value)?;
                    }
                    DocumentMutation::Upsert {
                        key,
                        value,
                        expected_version,
                    } => {
                        DocumentStore::apply_upsert_to_collection(
                            &mut collection,
                            &key,
                            value,
                            expected_version,
                        )?;
                    }
                    DocumentMutation::SoftDelete {
                        key,
                        expected_version,
                    } => {
                        DocumentStore::apply_soft_delete_to_collection(
                            &mut collection,
                            &key,
                            expected_version,
                        )?;
                    }
                }
            }

            let payload = DocumentStore::encode_collection_payload(&collection)?;
            Ok(PreparedWrite {
                target_path,
                payload_sha256: sha256_hex(&payload),
                payload,
                finalizer: Box::new(DocumentTargetFinalizer { store, collection }),
            })
        })
    }
}

struct DocumentTargetFinalizer<T> {
    store: DocumentStore<T>,
    collection: DocumentCollection<T>,
}

impl<T> BatchFinalizer for DocumentTargetFinalizer<T>
where
    T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
{
    fn finalize(self: Box<Self>) -> BatchFinalizeFuture {
        Box::pin(async move {
            self.store
                .install_committed_collection(self.collection)
                .await
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JournalWrite {
    target_path: PathBuf,
    staged_path: PathBuf,
    payload_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JournalEntry {
    batch_id: String,
    created_at: OffsetDateTime,
    writes: Vec<JournalWrite>,
}

#[derive(Debug, Clone)]
struct PendingJournalEntry {
    path: PathBuf,
    entry: JournalEntry,
}

#[derive(Debug, Clone, Copy, Default)]
struct CommitOptions {
    fail_after_targets_applied: Option<usize>,
}

/// Journal directory that makes local metadata write batches crash-recoverable.
#[derive(Debug, Clone)]
pub struct MetadataJournal {
    root: PathBuf,
    write_guard: Arc<Mutex<()>>,
}

impl MetadataJournal {
    /// Open or create the journal directory and recover any interrupted batches.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(&root).await.map_err(|error| {
            PlatformError::unavailable("failed to create metadata journal directory")
                .with_detail(error.to_string())
        })?;
        secure_directory_permissions(&root).await?;
        let root = fs::canonicalize(&root).await.map_err(|error| {
            PlatformError::unavailable("failed to canonicalize metadata journal path")
                .with_detail(error.to_string())
        })?;
        secure_directory_permissions(&root).await?;

        let journal = Self {
            write_guard: shared_write_guard(&root),
            root,
        };
        let _guard = journal.write_guard.clone().lock_owned().await;
        journal.recover_pending_locked().await?;
        Ok(journal)
    }

    /// Create one new write batch rooted in this journal.
    pub fn batch(&self) -> MetadataWriteBatch {
        MetadataWriteBatch::new(self.clone())
    }

    /// Replay and clear any interrupted batches that still exist on disk.
    pub async fn recover_pending(&self) -> Result<()> {
        let _guard = self.write_guard.clone().lock_owned().await;
        self.recover_pending_locked().await
    }

    async fn recover_pending_locked(&self) -> Result<()> {
        for path in self.entry_paths().await? {
            let pending = self.read_entry(&path).await?;
            let target_paths = pending
                .entry
                .writes
                .iter()
                .map(|write| write.target_path.clone())
                .collect::<Vec<_>>();
            let _guards = lock_paths(&target_paths).await;
            self.apply_entry(&pending, CommitOptions::default()).await?;
            self.remove_entry(&pending).await?;
        }
        Ok(())
    }

    async fn entry_paths(&self) -> Result<Vec<PathBuf>> {
        let mut entries = fs::read_dir(&self.root).await.map_err(|error| {
            PlatformError::unavailable("failed to read metadata journal directory")
                .with_detail(error.to_string())
        })?;
        let mut paths = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|error| {
            PlatformError::unavailable("failed to enumerate metadata journal entries")
                .with_detail(error.to_string())
        })? {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) == Some("json") {
                paths.push(path);
            }
        }
        paths.sort();
        Ok(paths)
    }

    async fn read_entry(&self, path: &Path) -> Result<PendingJournalEntry> {
        let raw = fs::read(path).await.map_err(|error| {
            PlatformError::unavailable("failed to read metadata journal entry")
                .with_detail(error.to_string())
        })?;
        let entry = serde_json::from_slice(&raw).map_err(|error| {
            PlatformError::unavailable("failed to decode metadata journal entry")
                .with_detail(error.to_string())
        })?;
        Ok(PendingJournalEntry {
            path: path.to_path_buf(),
            entry,
        })
    }

    async fn stage_writes(&self, writes: &[PreparedWrite]) -> Result<PendingJournalEntry> {
        let batch_id = allocate_batch_id()?;
        let mut journal_writes = Vec::with_capacity(writes.len());

        for write in writes {
            let staged_path = unique_temp_path(&write.target_path);
            if let Err(error) = write_new_file(&staged_path, &write.payload).await {
                cleanup_staged_files(&journal_writes).await?;
                return Err(error);
            }
            journal_writes.push(JournalWrite {
                target_path: write.target_path.clone(),
                staged_path,
                payload_sha256: write.payload_sha256.clone(),
            });
        }

        let entry = JournalEntry {
            batch_id: batch_id.clone(),
            created_at: OffsetDateTime::now_utc(),
            writes: journal_writes,
        };
        let entry_path = self.root.join(format!("{batch_id}.json"));
        let payload = serde_json::to_vec(&entry).map_err(|error| {
            PlatformError::unavailable("failed to encode metadata journal entry")
                .with_detail(error.to_string())
        })?;

        if let Err(error) = write_file_atomic(&entry_path, &payload).await {
            cleanup_staged_files(&entry.writes).await?;
            return Err(error);
        }

        Ok(PendingJournalEntry {
            path: entry_path,
            entry,
        })
    }

    async fn install_write(&self, write: &JournalWrite) -> Result<()> {
        if path_exists(&write.staged_path).await? {
            fs::rename(&write.staged_path, &write.target_path)
                .await
                .map_err(|error| {
                    PlatformError::unavailable("failed to install metadata journal target file")
                        .with_detail(error.to_string())
                })?;
            secure_file_permissions(&write.target_path).await?;
            sync_parent_dir(&write.target_path).await?;
        } else if !target_matches_checksum(&write.target_path, &write.payload_sha256).await? {
            return Err(PlatformError::unavailable(
                "metadata journal target is missing committed payload",
            )
            .with_detail(write.target_path.display().to_string()));
        }

        Ok(())
    }

    async fn apply_entry(
        &self,
        pending: &PendingJournalEntry,
        options: CommitOptions,
    ) -> Result<()> {
        let mut applied = 0_usize;
        for write in &pending.entry.writes {
            self.install_write(write).await?;
            applied = applied.saturating_add(1);
            if let Some(limit) = options.fail_after_targets_applied
                && applied >= limit
            {
                return Err(PlatformError::unavailable(
                    "simulated metadata journal apply failure",
                ));
            }
        }
        Ok(())
    }

    async fn remove_entry(&self, pending: &PendingJournalEntry) -> Result<()> {
        match fs::remove_file(&pending.path).await {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(
                    PlatformError::unavailable("failed to remove metadata journal entry")
                        .with_detail(error.to_string()),
                );
            }
        }
        sync_parent_dir(&pending.path).await?;
        Ok(())
    }
}

/// One crash-recoverable local batch of metadata writes.
pub struct MetadataWriteBatch {
    journal: MetadataJournal,
    targets: std::collections::BTreeMap<PathBuf, Box<dyn BatchTarget>>,
}

impl MetadataWriteBatch {
    fn new(journal: MetadataJournal) -> Self {
        Self {
            journal,
            targets: BTreeMap::new(),
        }
    }

    /// Return `true` when this batch contains no queued target mutations.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Queue one metadata create against a local file-backed collection.
    pub fn create_metadata<T>(
        &mut self,
        collection: &MetadataCollection<T>,
        key: &str,
        value: T,
    ) -> Result<()>
    where
        T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
    {
        let store = collection.local_document_store().ok_or_else(|| {
            PlatformError::unavailable(
                "metadata write batch requires a local document-backed metadata collection",
            )
        })?;
        self.create_document(&store, key, value)
    }

    /// Queue one metadata upsert against a local file-backed collection.
    pub fn upsert_metadata<T>(
        &mut self,
        collection: &MetadataCollection<T>,
        key: &str,
        value: T,
        expected_version: Option<u64>,
    ) -> Result<()>
    where
        T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
    {
        let store = collection.local_document_store().ok_or_else(|| {
            PlatformError::unavailable(
                "metadata write batch requires a local document-backed metadata collection",
            )
        })?;
        self.upsert_document(&store, key, value, expected_version)
    }

    /// Queue one metadata soft-delete against a local file-backed collection.
    pub fn soft_delete_metadata<T>(
        &mut self,
        collection: &MetadataCollection<T>,
        key: &str,
        expected_version: Option<u64>,
    ) -> Result<()>
    where
        T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
    {
        let store = collection.local_document_store().ok_or_else(|| {
            PlatformError::unavailable(
                "metadata write batch requires a local document-backed metadata collection",
            )
        })?;
        self.soft_delete_document(&store, key, expected_version)
    }

    /// Queue one document create against a local file-backed store.
    pub fn create_document<T>(
        &mut self,
        store: &DocumentStore<T>,
        key: &str,
        value: T,
    ) -> Result<()>
    where
        T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
    {
        self.queue_document_mutation(
            store.clone(),
            DocumentMutation::Create {
                key: key.to_owned(),
                value,
            },
        )
    }

    /// Queue one document upsert against a local file-backed store.
    pub fn upsert_document<T>(
        &mut self,
        store: &DocumentStore<T>,
        key: &str,
        value: T,
        expected_version: Option<u64>,
    ) -> Result<()>
    where
        T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
    {
        self.queue_document_mutation(
            store.clone(),
            DocumentMutation::Upsert {
                key: key.to_owned(),
                value,
                expected_version,
            },
        )
    }

    /// Queue one document soft-delete against a local file-backed store.
    pub fn soft_delete_document<T>(
        &mut self,
        store: &DocumentStore<T>,
        key: &str,
        expected_version: Option<u64>,
    ) -> Result<()>
    where
        T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
    {
        self.queue_document_mutation(
            store.clone(),
            DocumentMutation::SoftDelete {
                key: key.to_owned(),
                expected_version,
            },
        )
    }

    /// Commit the queued mutations as one crash-recoverable local batch.
    pub async fn commit(self) -> Result<()> {
        self.commit_with_options(CommitOptions::default()).await
    }

    fn queue_document_mutation<T>(
        &mut self,
        store: DocumentStore<T>,
        operation: DocumentMutation<T>,
    ) -> Result<()>
    where
        T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
    {
        let path = store.path().to_path_buf();
        if let Some(target) = self.targets.get_mut(&path) {
            let Some(document_target) = target.as_any_mut().downcast_mut::<DocumentTarget<T>>()
            else {
                return Err(PlatformError::conflict(format!(
                    "metadata write batch target `{}` mixes incompatible document types",
                    path.display()
                )));
            };
            document_target.operations.push(operation);
            return Ok(());
        }

        self.targets
            .insert(path, Box::new(DocumentTarget::new(store, operation)));
        Ok(())
    }

    async fn commit_with_options(self, options: CommitOptions) -> Result<()> {
        if self.targets.is_empty() {
            return Ok(());
        }

        let _journal_guard = self.journal.write_guard.clone().lock_owned().await;
        self.journal.recover_pending_locked().await?;
        let target_paths = self.targets.keys().cloned().collect::<Vec<_>>();
        let _target_guards = lock_paths(&target_paths).await;

        let mut prepared = Vec::with_capacity(self.targets.len());
        for (_, target) in self.targets {
            prepared.push(target.prepare().await?);
        }

        let pending = self.journal.stage_writes(&prepared).await?;
        let mut applied_prepared = Vec::with_capacity(prepared.len());
        for (prepared_write, journal_write) in prepared.into_iter().zip(pending.entry.writes.iter())
        {
            match self.journal.install_write(journal_write).await {
                Ok(()) => {
                    applied_prepared.push(prepared_write);
                    if let Some(limit) = options.fail_after_targets_applied
                        && applied_prepared.len() >= limit
                    {
                        // Keep same-process readers aligned with any targets already installed
                        // before surfacing the partial-write failure to the caller.
                        for write in applied_prepared {
                            write.finalize().await?;
                        }
                        return Err(PlatformError::unavailable(
                            "simulated metadata journal apply failure",
                        ));
                    }
                }
                Err(error) => {
                    for write in applied_prepared {
                        write.finalize().await?;
                    }
                    return Err(error);
                }
            }
        }

        for write in applied_prepared {
            write.finalize().await?;
        }

        self.journal.remove_entry(&pending).await
    }

    #[cfg(test)]
    async fn commit_with_fail_after(self, target_count: usize) -> Result<()> {
        self.commit_with_options(CommitOptions {
            fail_after_targets_applied: Some(target_count),
        })
        .await
    }
}

fn allocate_batch_id() -> Result<String> {
    AuditId::generate()
        .map(|id| id.to_string())
        .map_err(|error| {
            PlatformError::unavailable("failed to allocate metadata journal batch id")
                .with_detail(error.to_string())
        })
}

async fn lock_paths(paths: &[PathBuf]) -> Vec<OwnedMutexGuard<()>> {
    let mut sorted = paths.to_vec();
    sorted.sort();
    sorted.dedup();

    let mut guards = Vec::with_capacity(sorted.len());
    for path in sorted {
        guards.push(shared_write_guard(&path).lock_owned().await);
    }
    guards
}

async fn write_new_file(path: &Path, payload: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }

    let mut file = options.open(path).await.map_err(|error| {
        PlatformError::unavailable("failed to open metadata journal file")
            .with_detail(error.to_string())
    })?;
    file.write_all(payload).await.map_err(|error| {
        PlatformError::unavailable("failed to write metadata journal file")
            .with_detail(error.to_string())
    })?;
    file.flush().await.map_err(|error| {
        PlatformError::unavailable("failed to flush metadata journal file")
            .with_detail(error.to_string())
    })?;
    file.sync_all().await.map_err(|error| {
        PlatformError::unavailable("failed to sync metadata journal file")
            .with_detail(error.to_string())
    })?;
    drop(file);

    secure_file_permissions(path).await?;
    sync_parent_dir(path).await?;
    Ok(())
}

async fn write_file_atomic(path: &Path, payload: &[u8]) -> Result<()> {
    let temp_path = unique_temp_path(path);
    if let Err(error) = write_new_file(&temp_path, payload).await {
        let _ = fs::remove_file(&temp_path).await;
        return Err(error);
    }

    if let Err(error) = fs::rename(&temp_path, path).await {
        let _ = fs::remove_file(&temp_path).await;
        return Err(
            PlatformError::unavailable("failed to install metadata journal file")
                .with_detail(error.to_string()),
        );
    }

    secure_file_permissions(path).await?;
    sync_parent_dir(path).await?;
    Ok(())
}

async fn cleanup_staged_files(writes: &[JournalWrite]) -> Result<()> {
    for write in writes {
        match fs::remove_file(&write.staged_path).await {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(PlatformError::unavailable(
                    "failed to clean up staged metadata journal file",
                )
                .with_detail(error.to_string()));
            }
        }
    }
    Ok(())
}

async fn path_exists(path: &Path) -> Result<bool> {
    match fs::metadata(path).await {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(
            PlatformError::unavailable("failed to read metadata journal path")
                .with_detail(error.to_string()),
        ),
    }
}

async fn target_matches_checksum(path: &Path, expected_sha256: &str) -> Result<bool> {
    let payload = match fs::read(path).await {
        Ok(payload) => payload,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(
                PlatformError::unavailable("failed to read metadata journal target")
                    .with_detail(error.to_string()),
            );
        }
    };
    Ok(sha256_hex(&payload) == expected_sha256)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tokio::fs;

    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use tempfile::tempdir;
    use time::OffsetDateTime;

    use uhost_core::ErrorCode;

    use crate::{
        DeliveryState, DurableOutbox, OutboxMessage, WorkflowInstance, WorkflowPhase, WorkflowStep,
        WorkflowStepState,
    };

    use super::{DocumentStore, MetadataCollection, MetadataJournal};

    const RECOVERY_WORKFLOW_ID: &str = "workflow-1";
    const RECOVERY_EFFECT_KEY: &str = "effect:workflow-1";
    const RECOVERY_OUTBOX_ID: &str = "message:workflow-1";
    const RECOVERY_OUTBOX_IDEMPOTENCY_KEY: &str = "workflow-1:completed";

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct PrimaryRecord {
        email: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct EmailIndexRecord {
        user_id: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct RecoveryWorkflowState {
        effect_key: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct SideEffectRecord {
        workflow_id: String,
        status: String,
    }

    struct RecoveryHarness {
        journal: MetadataJournal,
        workflows: DocumentStore<WorkflowInstance<RecoveryWorkflowState>>,
        effects: MetadataCollection<SideEffectRecord>,
        outbox_store: DocumentStore<OutboxMessage<serde_json::Value>>,
        outbox: DurableOutbox<serde_json::Value>,
    }

    async fn open_recovery_harness(root: &Path) -> RecoveryHarness {
        let workflows_path = root.join("a_workflows.json");
        let effects_path = root.join("m_effects.json");
        let outbox_path = root.join("z_outbox.json");

        RecoveryHarness {
            journal: MetadataJournal::open(root.join("journal"))
                .await
                .unwrap_or_else(|error| panic!("{error}")),
            workflows: DocumentStore::<WorkflowInstance<RecoveryWorkflowState>>::open(
                &workflows_path,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}")),
            effects: MetadataCollection::<SideEffectRecord>::open_local(&effects_path)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
            outbox_store: DocumentStore::<OutboxMessage<serde_json::Value>>::open(&outbox_path)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
            outbox: DurableOutbox::<serde_json::Value>::open(&outbox_path)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        }
    }

    fn recovery_workflow() -> WorkflowInstance<RecoveryWorkflowState> {
        let mut workflow = WorkflowInstance::new(
            RECOVERY_WORKFLOW_ID,
            "example.workflow.recovery",
            "example_subject",
            "subject-1",
            RecoveryWorkflowState {
                effect_key: String::from(RECOVERY_EFFECT_KEY),
            },
            vec![
                WorkflowStep::new("apply_side_effect", 0),
                WorkflowStep::new("persist_completion", 1),
            ],
        );
        workflow.set_phase(WorkflowPhase::Running);
        workflow.current_step_index = Some(0);
        workflow
            .step_mut(0)
            .unwrap_or_else(|| panic!("missing side effect workflow step"))
            .transition(
                WorkflowStepState::Active,
                Some(String::from("intent persisted")),
            );
        workflow
    }

    fn completed_recovery_workflow(
        mut workflow: WorkflowInstance<RecoveryWorkflowState>,
    ) -> WorkflowInstance<RecoveryWorkflowState> {
        workflow.current_step_index = Some(1);
        workflow
            .step_mut(0)
            .unwrap_or_else(|| panic!("missing side effect workflow step"))
            .transition(
                WorkflowStepState::Completed,
                Some(String::from("side effect applied")),
            );
        workflow
            .step_mut(1)
            .unwrap_or_else(|| panic!("missing completion workflow step"))
            .transition(
                WorkflowStepState::Completed,
                Some(String::from("completion persisted")),
            );
        workflow.set_phase(WorkflowPhase::Completed);
        workflow
    }

    fn recovery_outbox_message() -> OutboxMessage<serde_json::Value> {
        let now = OffsetDateTime::now_utc();
        OutboxMessage {
            id: String::from(RECOVERY_OUTBOX_ID),
            topic: String::from("workflow.events.v1"),
            idempotency_key: Some(String::from(RECOVERY_OUTBOX_IDEMPOTENCY_KEY)),
            payload: json!({
                "workflow_id": RECOVERY_WORKFLOW_ID,
                "status": "completed"
            }),
            created_at: now,
            updated_at: now,
            state: DeliveryState::Pending,
        }
    }

    async fn count_journal_entries(journal_path: &Path) -> usize {
        let mut count = 0_usize;
        let mut entries = fs::read_dir(journal_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        while let Some(entry) = entries
            .next_entry()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
        {
            if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
                count = count.saturating_add(1);
            }
        }
        count
    }

    #[tokio::test]
    async fn write_batch_commits_primary_index_and_outbox_together() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let journal = MetadataJournal::open(temp.path().join("journal"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let primary =
            MetadataCollection::<PrimaryRecord>::open_local(temp.path().join("users.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let secondary = MetadataCollection::<EmailIndexRecord>::open_local(
            temp.path().join("users_by_email.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let outbox_store = DocumentStore::<OutboxMessage<serde_json::Value>>::open(
            temp.path().join("outbox.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let outbox = DurableOutbox::<serde_json::Value>::open(temp.path().join("outbox.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let now = OffsetDateTime::now_utc();
        let mut batch = journal.batch();
        batch
            .create_metadata(
                &primary,
                "user-1",
                PrimaryRecord {
                    email: String::from("user@example.com"),
                },
            )
            .unwrap_or_else(|error| panic!("{error}"));
        batch
            .create_metadata(
                &secondary,
                "user@example.com",
                EmailIndexRecord {
                    user_id: String::from("user-1"),
                },
            )
            .unwrap_or_else(|error| panic!("{error}"));
        batch
            .create_document(
                &outbox_store,
                "message-1",
                OutboxMessage {
                    id: String::from("message-1"),
                    topic: String::from("identity.events.v1"),
                    idempotency_key: Some(String::from("idem-1")),
                    payload: json!({"kind":"user_created","user_id":"user-1"}),
                    created_at: now,
                    updated_at: now,
                    state: DeliveryState::Pending,
                },
            )
            .unwrap_or_else(|error| panic!("{error}"));

        batch
            .commit()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored_user = primary
            .get("user-1")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing primary record"));
        assert_eq!(stored_user.value.email, "user@example.com");

        let stored_index = secondary
            .get("user@example.com")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing secondary index"));
        assert_eq!(stored_index.value.user_id, "user-1");

        let messages = outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, "message-1");
    }

    #[tokio::test]
    async fn write_batch_leaves_no_partial_writes_when_one_target_conflicts() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let journal = MetadataJournal::open(temp.path().join("journal"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let primary =
            MetadataCollection::<PrimaryRecord>::open_local(temp.path().join("users.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let secondary = MetadataCollection::<EmailIndexRecord>::open_local(
            temp.path().join("users_by_email.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let outbox_store = DocumentStore::<OutboxMessage<serde_json::Value>>::open(
            temp.path().join("outbox.json"),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let outbox = DurableOutbox::<serde_json::Value>::open(temp.path().join("outbox.json"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        secondary
            .create(
                "user@example.com",
                EmailIndexRecord {
                    user_id: String::from("existing-user"),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let now = OffsetDateTime::now_utc();
        let mut batch = journal.batch();
        batch
            .create_metadata(
                &primary,
                "user-1",
                PrimaryRecord {
                    email: String::from("user@example.com"),
                },
            )
            .unwrap_or_else(|error| panic!("{error}"));
        batch
            .create_metadata(
                &secondary,
                "user@example.com",
                EmailIndexRecord {
                    user_id: String::from("user-1"),
                },
            )
            .unwrap_or_else(|error| panic!("{error}"));
        batch
            .create_document(
                &outbox_store,
                "message-1",
                OutboxMessage {
                    id: String::from("message-1"),
                    topic: String::from("identity.events.v1"),
                    idempotency_key: None,
                    payload: json!({"kind":"user_created","user_id":"user-1"}),
                    created_at: now,
                    updated_at: now,
                    state: DeliveryState::Pending,
                },
            )
            .unwrap_or_else(|error| panic!("{error}"));

        let error = batch
            .commit()
            .await
            .expect_err("conflicting secondary index should fail the batch");
        assert_eq!(error.code, ErrorCode::Conflict);

        assert!(
            primary
                .get("user-1")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );
        let messages = outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(messages.is_empty());
    }

    #[tokio::test]
    async fn journal_recovers_batch_after_partial_apply() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let journal_path = temp.path().join("journal");
        let primary_path = temp.path().join("users.json");
        let secondary_path = temp.path().join("users_by_email.json");
        let outbox_path = temp.path().join("outbox.json");

        let journal = MetadataJournal::open(&journal_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let primary = MetadataCollection::<PrimaryRecord>::open_local(&primary_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let secondary = MetadataCollection::<EmailIndexRecord>::open_local(&secondary_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let outbox_store = DocumentStore::<OutboxMessage<serde_json::Value>>::open(&outbox_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let now = OffsetDateTime::now_utc();
        let mut batch = journal.batch();
        batch
            .create_metadata(
                &primary,
                "user-1",
                PrimaryRecord {
                    email: String::from("user@example.com"),
                },
            )
            .unwrap_or_else(|error| panic!("{error}"));
        batch
            .create_metadata(
                &secondary,
                "user@example.com",
                EmailIndexRecord {
                    user_id: String::from("user-1"),
                },
            )
            .unwrap_or_else(|error| panic!("{error}"));
        batch
            .create_document(
                &outbox_store,
                "message-1",
                OutboxMessage {
                    id: String::from("message-1"),
                    topic: String::from("identity.events.v1"),
                    idempotency_key: Some(String::from("idem-1")),
                    payload: json!({"kind":"user_created","user_id":"user-1"}),
                    created_at: now,
                    updated_at: now,
                    state: DeliveryState::Pending,
                },
            )
            .unwrap_or_else(|error| panic!("{error}"));

        let error = batch
            .commit_with_fail_after(1)
            .await
            .expect_err("failpoint should interrupt the batch");
        assert_eq!(error.code, ErrorCode::Unavailable);

        let _recovered = MetadataJournal::open(&journal_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let reopened_primary = MetadataCollection::<PrimaryRecord>::open_local(&primary_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let reopened_secondary =
            MetadataCollection::<EmailIndexRecord>::open_local(&secondary_path)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let outbox = DurableOutbox::<serde_json::Value>::open(&outbox_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(
            reopened_primary
                .get("user-1")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_some()
        );
        assert!(
            reopened_secondary
                .get("user@example.com")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_some()
        );
        let messages = outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(messages.len(), 1);

        let mut entries = fs::read_dir(&journal_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let next = entries
            .next_entry()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(next.is_none());
    }

    #[tokio::test]
    async fn journal_recovery_replays_intent_side_effect_completion_and_outbox_sequence() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let journal_path = temp.path().join("journal");

        let harness = open_recovery_harness(temp.path()).await;
        let mut intent_batch = harness.journal.batch();
        intent_batch
            .create_document(
                &harness.workflows,
                RECOVERY_WORKFLOW_ID,
                recovery_workflow(),
            )
            .unwrap_or_else(|error| panic!("{error}"));

        let error = intent_batch
            .commit_with_fail_after(1)
            .await
            .expect_err("intent failpoint should interrupt the batch");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert_eq!(count_journal_entries(&journal_path).await, 1);

        let recovered_after_intent = open_recovery_harness(temp.path()).await;
        let stored_intent = recovered_after_intent
            .workflows
            .get(RECOVERY_WORKFLOW_ID)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing recovered workflow intent"));
        assert_eq!(stored_intent.value.phase, WorkflowPhase::Running);
        assert_eq!(stored_intent.value.current_step_index, Some(0));
        assert_eq!(
            stored_intent.value.steps[0].state,
            WorkflowStepState::Active
        );
        assert_eq!(count_journal_entries(&journal_path).await, 0);
        assert!(
            recovered_after_intent
                .effects
                .get(RECOVERY_EFFECT_KEY)
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );
        assert!(
            recovered_after_intent
                .outbox
                .list_all()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_empty()
        );

        let mut side_effect_batch = recovered_after_intent.journal.batch();
        side_effect_batch
            .create_metadata(
                &recovered_after_intent.effects,
                RECOVERY_EFFECT_KEY,
                SideEffectRecord {
                    workflow_id: String::from(RECOVERY_WORKFLOW_ID),
                    status: String::from("applied"),
                },
            )
            .unwrap_or_else(|error| panic!("{error}"));

        let error = side_effect_batch
            .commit_with_fail_after(1)
            .await
            .expect_err("side effect failpoint should interrupt the batch");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert_eq!(count_journal_entries(&journal_path).await, 1);

        let recovered_after_side_effect = open_recovery_harness(temp.path()).await;
        let stored_effect = recovered_after_side_effect
            .effects
            .get(RECOVERY_EFFECT_KEY)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing recovered side effect"));
        assert_eq!(stored_effect.value.workflow_id, RECOVERY_WORKFLOW_ID);
        assert_eq!(stored_effect.value.status, "applied");
        let running_workflow = recovered_after_side_effect
            .workflows
            .get(RECOVERY_WORKFLOW_ID)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing workflow after side effect recovery"));
        assert_eq!(running_workflow.value.phase, WorkflowPhase::Running);
        assert_eq!(count_journal_entries(&journal_path).await, 0);
        assert!(
            recovered_after_side_effect
                .outbox
                .list_all()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_empty()
        );

        let mut completion_batch = recovered_after_side_effect.journal.batch();
        let completed_workflow = completed_recovery_workflow(running_workflow.value);
        let outbox_message = recovery_outbox_message();
        completion_batch
            .upsert_document(
                &recovered_after_side_effect.workflows,
                RECOVERY_WORKFLOW_ID,
                completed_workflow,
                Some(running_workflow.version),
            )
            .unwrap_or_else(|error| panic!("{error}"));
        completion_batch
            .create_document(
                &recovered_after_side_effect.outbox_store,
                RECOVERY_OUTBOX_ID,
                outbox_message.clone(),
            )
            .unwrap_or_else(|error| panic!("{error}"));

        let error = completion_batch
            .commit_with_fail_after(1)
            .await
            .expect_err("completion failpoint should interrupt the batch");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert_eq!(count_journal_entries(&journal_path).await, 1);

        let partially_completed = recovered_after_side_effect
            .workflows
            .get(RECOVERY_WORKFLOW_ID)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing partially recovered workflow"));
        assert_eq!(partially_completed.value.phase, WorkflowPhase::Completed);
        assert!(
            recovered_after_side_effect
                .outbox
                .list_all()
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_empty()
        );

        let recovered_final = open_recovery_harness(temp.path()).await;
        let completed_workflow = recovered_final
            .workflows
            .get(RECOVERY_WORKFLOW_ID)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing workflow after final recovery"));
        assert_eq!(completed_workflow.value.phase, WorkflowPhase::Completed);
        assert_eq!(completed_workflow.value.current_step_index, Some(1));
        assert_eq!(
            completed_workflow.value.steps[0].state,
            WorkflowStepState::Completed
        );
        assert_eq!(
            completed_workflow.value.steps[1].state,
            WorkflowStepState::Completed
        );
        assert!(completed_workflow.value.completed_at.is_some());

        let messages = recovered_final
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, outbox_message.id);
        assert_eq!(
            messages[0].idempotency_key.as_deref(),
            Some(RECOVERY_OUTBOX_IDEMPOTENCY_KEY)
        );
        assert_eq!(count_journal_entries(&journal_path).await, 0);
    }
}
