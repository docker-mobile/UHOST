//! Durable storage adapters for the all-in-one platform mode.
//!
//! The default implementation is intentionally simple and portable: JSON
//! documents for metadata, append-only JSON lines for audit/event streams, and a
//! content-addressed blob store for opaque payloads. Service crates depend on
//! these adapters through explicit types so stronger distributed backends can be
//! introduced without changing domain logic.

pub mod audit;
pub mod blob;
pub mod delivery;
pub mod document;
pub mod journal;
pub mod lease;
pub mod metadata;
pub mod registry;
pub mod relay;
pub mod workflow;

pub use audit::AuditLog;
pub use blob::{BlobMetadata, BlobStore};
pub use delivery::{DeliveryState, DurableInbox, DurableOutbox, InboxRecord, OutboxMessage};
pub use document::{
    DocumentChange, DocumentChangePage, DocumentCollection, DocumentCursor,
    DocumentSnapshotCheckpoint, DocumentStore, StoredDocument,
};
pub use journal::{MetadataJournal, MetadataWriteBatch};
pub use lease::{
    LeaseDrainIntent, LeaseFreshness, LeaseReadiness, LeaseRegistrationChange,
    LeaseRegistrationChangePage, LeaseRegistrationCollection, LeaseRegistrationCursor,
    LeaseRegistrationRecord, LeaseRegistrationSnapshotCheckpoint, LeaseRegistrationStore,
    LeaseResultFuture,
};
pub use metadata::{
    MetadataChange, MetadataChangePage, MetadataCollection, MetadataCursor, MetadataListCursor,
    MetadataListFilter, MetadataListPage, MetadataResultFuture, MetadataResumeToken,
    MetadataSnapshotCheckpoint, MetadataStore, MetadataWatchBatch, MetadataWatchError,
    MetadataWatchEvent, MetadataWatchEventKind, MetadataWatchRequest, MetadataWatchResult,
    MetadataWatchResultFuture, MetadataWatcher,
};
pub use registry::{
    BoundedContextCoordinationModel, BoundedContextOwnershipScope,
    BoundedContextSafetyMatrixCollection, BoundedContextSafetyPolicy, BoundedContextSafetyRecord,
    CellDirectoryChange, CellDirectoryChangePage, CellDirectoryCollection, CellDirectoryCursor,
    CellDirectoryRecord, CellDirectoryResultFuture, CellDirectorySnapshotCheckpoint,
    CellDirectoryStore, CellHomeLineage, CellHomeLocation, CellHomeProjectionChange,
    CellHomeProjectionChangePage, CellHomeProjectionCollection, CellHomeProjectionCursor,
    CellHomeProjectionRecord, CellHomeSubjectKind, CellParticipantDegradedReason,
    CellParticipantDrainPhase, CellParticipantLeaseSource, CellParticipantLeaseState,
    CellParticipantReconciliationState, CellParticipantRecord, CellParticipantState,
    CellServiceGroupConflictState, CellServiceGroupDirectoryChange,
    CellServiceGroupDirectoryChangePage, CellServiceGroupDirectoryCollection,
    CellServiceGroupDirectoryCursor, CellServiceGroupDirectoryEntry,
    CellServiceGroupDirectoryRecord, CellServiceGroupDirectoryResultFuture,
    CellServiceGroupDirectorySnapshotCheckpoint, CellServiceGroupDirectoryStore,
    CellServiceGroupRegistrationResolution, EvacuationRollbackArtifact,
    EvacuationRouteWithdrawalArtifact, EvacuationTargetReadinessArtifact, LocalCellRegistry,
    LocalCellRegistryCacheSnapshot, LocalCellRegistryDraft, LocalCellRegistryPublication,
    LocalCellRegistryState, ParticipantTombstoneHistoryCollection,
    ParticipantTombstoneHistoryRecord, RegionDirectoryRecord, ServiceEndpointBinding,
    ServiceEndpointChange, ServiceEndpointChangePage, ServiceEndpointCollection,
    ServiceEndpointCursor, ServiceEndpointProtocol, ServiceEndpointRecord,
    ServiceGroupDiscoveryCellProjection, ServiceGroupDiscoveryCollection,
    ServiceGroupDiscoveryProjector, ServiceGroupDiscoveryRecord,
    ServiceGroupDiscoveryRegionProjection, ServiceGroupDiscoveryState, ServiceInstanceChange,
    ServiceInstanceChangePage, ServiceInstanceCollection, ServiceInstanceCursor,
    ServiceInstanceRecord, StaleParticipantCleanupAction, StaleParticipantCleanupStage,
    StaleParticipantCleanupWorkflowState, cell_home_projection_key,
    converge_cell_directory_from_registry_cache, converge_cell_directory_participants_at,
    resolve_cell_service_group_directory, resolve_cell_service_group_directory_with_safety_matrix,
    resolve_cell_service_instances, resolve_service_group_discovery, service_endpoint_record_id,
    service_instance_record_id, stale_participant_cleanup_workflow,
    stale_participant_cleanup_workflow_id,
};
pub use relay::{
    DurableEventRelay, EventRelayEnvelope, RelayCursor, RelayEnvelopeChange,
    RelayEnvelopeChangePage, RelayPublishRequest, RelayStatus,
};
pub use workflow::{
    WorkflowCollection, WorkflowEffectLedgerRecord, WorkflowInstance, WorkflowPhase,
    WorkflowResultFuture, WorkflowRunnerClaim, WorkflowStep, WorkflowStepEffect,
    WorkflowStepEffectExecution, WorkflowStepEffectState, WorkflowStepState, WorkflowStore,
};
