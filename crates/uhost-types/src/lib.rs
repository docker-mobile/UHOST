//! Shared types used across the Project UHost workspace.
//!
//! This crate intentionally carries only the domain contracts that need to be
//! stable between services: typed identifiers, resource metadata, API list
//! contracts, and event envelopes. Keeping these definitions in one place makes
//! wire compatibility explicit and reduces the chance that two services silently
//! diverge on the same concept.

pub mod common;
pub mod contracts;
pub mod event;
pub mod id;

pub use common::{
    AuditActor, EdgeDnsBinding, EdgeExposureIntent, EdgePrivateNetworkAttachment, EdgePublication,
    EdgePublicationTarget, EdgeSecurityPolicyAttachment, GovernanceChangeAuthorization,
    GovernanceRequestProvenance, OwnershipScope, PrincipalIdentity, PrincipalKind, PriorityClass,
    PrivateNetworkTopologyReadiness, Protocol, QuotaWindow, ResourceLifecycleState,
    ResourceMetadata, ServiceMode,
};
pub use contracts::{
    ConcurrencyToken, FilterPredicate, IdempotencyKey, ListRequest, Page, PageCursor, SortDirection,
};
pub use event::{EventHeader, EventPayload, PlatformEvent, ServiceEvent};
pub use id::{
    AbuseAppealId, AbuseCaseId, AbuseQuarantineId, AbuseSignalId, AlertRuleId, ApiKeyId,
    ApprovalId, ArchiveId, AuditCheckpointId, AuditId, BillingAccountId, BucketId, CacheClusterId,
    ChangeRequestId, DatabaseId, DeadLetterId, DeploymentId, DnsPublicationIntentId,
    DurabilityTierId, EdgePublicationTargetId, EgressRuleId, EnvironmentId, FailoverOperationId,
    FileShareId, FlowAuditId, IdError, InvitationId, InvoiceId, IpSetId, LeaderLeaseId,
    LegalHoldId, MailDomainId, MailRouteId, MigrationJobId, NatGatewayId, NetPolicyId, NextHopId,
    NodeId, NotificationId, NotificationPreferenceId, NotificationTemplateId, OrganizationId,
    PeeringConnectionId, PluginId, PolicyId, PrivateNetworkId, PrivateRouteId, ProjectId, QueueId,
    RehydrateJobId, RepairJobId, ReplicationStreamId, RetentionPolicyId, RolloutPlanId, RouteId,
    RouteTableId, SecretId, ServiceConnectAttachmentId, ServiceIdentityId, SessionId,
    ShardPlacementId, StorageClassId, SubnetId, SubscriptionId, TenantId, TransitAttachmentId,
    UploadId, UserId, UvmBenchmarkBaselineId, UvmBenchmarkCampaignId, UvmBenchmarkResultId,
    UvmCheckpointId, UvmClaimDecisionId, UvmCompatibilityReportId, UvmDeviceProfileId,
    UvmFailureReportId, UvmFirmwareBundleId, UvmGuestProfileId, UvmHostEvidenceId, UvmImageId,
    UvmInstanceId, UvmMigrationId, UvmNodeCapabilityId, UvmNodeDrainId, UvmOverlayPolicyId,
    UvmPerfAttestationId, UvmRegionCellPolicyId, UvmRuntimeSessionId, UvmSnapshotId, UvmTemplateId,
    VolumeId, VpnConnectionId, WebhookEndpointId, WorkloadId, WorkloadIdentityId, ZoneId,
};
