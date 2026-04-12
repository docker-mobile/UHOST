use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use time::OffsetDateTime;
use uhost_core::{PlatformError, Result, SecretBytes};
use uhost_runtime::{
    ForwardedServiceRegistration, HttpService, InternalRouteAudienceBinding, RouteRequestClass,
    RouteSurface, RouteSurfaceBinding, RuntimeCellMembership, RuntimeDrainIntent,
    RuntimeEvacuationRollbackArtifact, RuntimeEvacuationRouteWithdrawalArtifact,
    RuntimeEvacuationTargetReadinessArtifact, RuntimeLeaseFreshness, RuntimeLeaseState,
    RuntimeLogicalServiceGroup, RuntimeParticipantCleanupStage, RuntimeParticipantCleanupWorkflow,
    RuntimeParticipantDegradedReason, RuntimeParticipantDrainPhase, RuntimeParticipantLeaseSource,
    RuntimeParticipantReconciliation, RuntimeParticipantRegistration, RuntimeParticipantState,
    RuntimeParticipantTombstoneHistoryEntry, RuntimeProcessRole, RuntimeProcessState,
    RuntimeReadinessState, RuntimeRegionMembership, RuntimeServiceGroupConflictState,
    RuntimeServiceGroupDirectoryEntry, RuntimeServiceGroupRegistrationResolution, RuntimeTopology,
    ServiceRegistration,
};
use uhost_store::{
    CellDirectoryRecord, CellParticipantDegradedReason, CellParticipantDrainPhase,
    CellParticipantLeaseSource, CellParticipantLeaseState, CellParticipantReconciliationState,
    CellParticipantRecord, CellParticipantState, CellServiceGroupConflictState,
    CellServiceGroupDirectoryEntry, CellServiceGroupDirectoryRecord,
    CellServiceGroupRegistrationResolution, LeaseDrainIntent, LeaseFreshness, LeaseReadiness,
    LeaseRegistrationRecord, ParticipantTombstoneHistoryRecord, ServiceEndpointBinding,
    ServiceEndpointProtocol, StaleParticipantCleanupStage, StaleParticipantCleanupWorkflowState,
    WorkflowInstance, WorkflowPhase,
};
use uhost_svc_abuse::AbuseService;
use uhost_svc_billing::BillingService;
use uhost_svc_console::ConsoleService;
use uhost_svc_container::ContainerService;
use uhost_svc_control::ControlService;
use uhost_svc_data::DataService;
use uhost_svc_dns::DnsService;
use uhost_svc_governance::GovernanceService;
use uhost_svc_ha::HaService;
use uhost_svc_identity::IdentityService;
use uhost_svc_ingress::IngressService;
use uhost_svc_lifecycle::LifecycleService;
use uhost_svc_mail::MailService;
use uhost_svc_netsec::NetsecService;
use uhost_svc_node::NodeService;
use uhost_svc_notify::NotifyService;
use uhost_svc_observe::ObserveService;
use uhost_svc_policy::PolicyService;
use uhost_svc_scheduler::SchedulerService;
use uhost_svc_secrets::SecretsService;
use uhost_svc_storage::StorageService;
use uhost_svc_stream::StreamService;
use uhost_svc_tenancy::TenancyService;
use uhost_svc_uvm_control::UvmControlService;
use uhost_svc_uvm_image::UvmImageService;
use uhost_svc_uvm_node::UvmNodeService;
use uhost_svc_uvm_observe::UvmObserveService;
use uhost_types::ServiceMode;

use crate::{
    AllInOneConfig, RuntimeInternalService, RuntimeOperatorService,
    RuntimeProcessRegistrationContext,
};

const fn tenant_exact_read(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::exact_safe(path, RouteSurface::Tenant, RouteRequestClass::Read)
}

const fn tenant_exact_unsafe_read(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::exact_unsafe(path, RouteSurface::Tenant, RouteRequestClass::Read)
}

const fn tenant_exact_unsafe_async_mutate(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::exact_unsafe(path, RouteSurface::Tenant, RouteRequestClass::AsyncMutate)
}

const fn tenant_exact_operator_read(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::exact_safe(path, RouteSurface::Tenant, RouteRequestClass::OperatorRead)
}

const fn tenant_exact_unsafe_operator_mutate(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::exact_unsafe(
        path,
        RouteSurface::Tenant,
        RouteRequestClass::OperatorMutate,
    )
}

const fn tenant_prefix_safe_read(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::prefix_safe(path, RouteSurface::Tenant, RouteRequestClass::Read)
}

const fn tenant_prefix_unsafe_async_mutate(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::prefix_unsafe(path, RouteSurface::Tenant, RouteRequestClass::AsyncMutate)
}

const fn tenant_prefix_safe_control_read(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::prefix_safe(path, RouteSurface::Tenant, RouteRequestClass::ControlRead)
}

const fn tenant_prefix_unsafe_mutate(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::prefix_unsafe(path, RouteSurface::Tenant, RouteRequestClass::Mutate)
}

const fn tenant_prefix_safe_operator_read(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::prefix_safe(path, RouteSurface::Tenant, RouteRequestClass::OperatorRead)
}

const fn tenant_prefix_unsafe_operator_mutate(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::prefix_unsafe(
        path,
        RouteSurface::Tenant,
        RouteRequestClass::OperatorMutate,
    )
}

const fn operator_exact_read(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::exact_safe(
        path,
        RouteSurface::Operator,
        RouteRequestClass::OperatorRead,
    )
}

const fn operator_prefix_safe_read(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::prefix_safe(
        path,
        RouteSurface::Operator,
        RouteRequestClass::OperatorRead,
    )
}

const fn operator_prefix_unsafe_mutate(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::prefix_unsafe(
        path,
        RouteSurface::Operator,
        RouteRequestClass::OperatorMutate,
    )
}

const fn operator_exact_destructive(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::exact_unsafe(
        path,
        RouteSurface::Operator,
        RouteRequestClass::OperatorDestructive,
    )
}

const fn internal_exact(path: &'static str) -> RouteSurfaceBinding {
    RouteSurfaceBinding::exact(path, RouteSurface::Internal, RouteRequestClass::Read)
}

const fn internal_audience_exact(
    path: &'static str,
    audience: &'static str,
) -> InternalRouteAudienceBinding {
    InternalRouteAudienceBinding::exact(path, audience)
}

const RUNTIME_TOMBSTONE_HISTORY_LIMIT: usize = 25;
const NO_INTERNAL_ROUTE_AUDIENCES: &[InternalRouteAudienceBinding] = &[];

const CONSOLE_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_exact_read("/"),
    tenant_prefix_safe_read("/console"),
    tenant_prefix_unsafe_async_mutate("/console"),
];
const RUNTIME_OPERATOR_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    operator_exact_destructive("/runtime/participants/tombstone"),
    operator_exact_read("/runtime/participants/tombstone-history"),
    operator_exact_read("/runtime/participants/tombstone-history/aggregated"),
];
pub(crate) const RUNTIME_INTERNAL_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    internal_exact("/internal/runtime/routes"),
    internal_exact("/internal/runtime/topology"),
];
pub(crate) const RUNTIME_INTERNAL_ROUTE_AUDIENCES: &[InternalRouteAudienceBinding] = &[
    internal_audience_exact("/internal/runtime/routes", "runtime"),
    internal_audience_exact("/internal/runtime/topology", "runtime"),
];
const IDENTITY_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_exact_read("/identity"),
    tenant_prefix_safe_operator_read("/identity"),
    tenant_prefix_unsafe_operator_mutate("/identity"),
];
const TENANCY_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/tenancy"),
    tenant_prefix_unsafe_async_mutate("/tenancy"),
];
const CONTROL_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/control"),
    tenant_prefix_unsafe_async_mutate("/control"),
];
const CONTAINER_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/container"),
    tenant_prefix_unsafe_async_mutate("/container"),
];
const SCHEDULER_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/scheduler"),
    tenant_prefix_unsafe_async_mutate("/scheduler"),
];
const NODE_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/node"),
    tenant_prefix_unsafe_async_mutate("/node"),
];
const INGRESS_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/ingress"),
    tenant_prefix_unsafe_async_mutate("/ingress"),
];
const DNS_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/dns"),
    tenant_prefix_unsafe_async_mutate("/dns"),
];
const NETSEC_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/netsec"),
    tenant_prefix_unsafe_async_mutate("/netsec"),
];
const STORAGE_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_exact_operator_read("/storage/volumes/{volume_id}/snapshot-policy"),
    tenant_exact_operator_read("/storage/volumes/{volume_id}/recovery-point"),
    tenant_exact_operator_read("/storage/volumes/{volume_id}/recovery-history"),
    tenant_exact_operator_read("/storage/volumes/{volume_id}/restore-actions"),
    tenant_exact_unsafe_operator_mutate("/storage/volumes/{volume_id}/restore-actions"),
    tenant_exact_operator_read("/storage/restore-actions/{action_id}"),
    tenant_prefix_safe_read("/storage"),
    tenant_prefix_unsafe_async_mutate("/storage"),
];
const DATA_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/data"),
    tenant_prefix_unsafe_async_mutate("/data"),
    tenant_exact_operator_read("/data/backups/{backup_id}/storage-lineage"),
    tenant_exact_operator_read("/data/restores/{restore_id}/storage-lineage"),
];
const STREAM_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/stream"),
    tenant_prefix_unsafe_async_mutate("/stream"),
];
const MAIL_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/mail"),
    tenant_prefix_unsafe_async_mutate("/mail"),
];
const GOVERNANCE_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_control_read("/governance"),
    tenant_prefix_unsafe_mutate("/governance"),
    tenant_exact_unsafe_read("/governance/retention-evaluate"),
];
const HA_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/ha"),
    tenant_prefix_unsafe_async_mutate("/ha"),
];
const LIFECYCLE_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/lifecycle"),
    tenant_prefix_unsafe_async_mutate("/lifecycle"),
];
const SECRETS_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_control_read("/secrets"),
    tenant_prefix_unsafe_mutate("/secrets"),
];
const BILLING_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/billing"),
    tenant_prefix_unsafe_async_mutate("/billing"),
];
const NOTIFY_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/notify"),
    tenant_prefix_unsafe_async_mutate("/notify"),
];
const OBSERVE_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_read("/observe"),
    tenant_prefix_unsafe_async_mutate("/observe"),
];
const POLICY_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_control_read("/policy"),
    tenant_prefix_unsafe_mutate("/policy"),
    tenant_exact_unsafe_read("/policy/evaluate"),
];
const ABUSE_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_prefix_safe_operator_read("/abuse/remediation-cases"),
    tenant_prefix_unsafe_operator_mutate("/abuse/remediation-cases"),
    tenant_prefix_safe_read("/abuse"),
    tenant_prefix_unsafe_async_mutate("/abuse"),
];
const UVM_CONTROL_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_exact_read("/uvm"),
    operator_exact_read("/uvm/control/summary"),
    tenant_prefix_safe_read("/uvm/templates"),
    tenant_prefix_unsafe_async_mutate("/uvm/templates"),
    tenant_prefix_safe_read("/uvm/instances"),
    tenant_prefix_unsafe_async_mutate("/uvm/instances"),
    tenant_prefix_safe_read("/uvm/snapshots"),
    tenant_prefix_unsafe_async_mutate("/uvm/snapshots"),
    tenant_prefix_safe_read("/uvm/migrations"),
    tenant_prefix_unsafe_async_mutate("/uvm/migrations"),
    operator_prefix_safe_read("/uvm/reconciliation"),
    operator_prefix_unsafe_mutate("/uvm/reconciliation"),
    operator_prefix_safe_read("/uvm/outbox"),
    operator_prefix_unsafe_mutate("/uvm/outbox"),
];
const UVM_IMAGE_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    tenant_exact_read("/uvm/image"),
    tenant_prefix_safe_read("/uvm/images"),
    tenant_prefix_unsafe_async_mutate("/uvm/images"),
    tenant_prefix_safe_read("/uvm/firmware-bundles"),
    tenant_prefix_unsafe_async_mutate("/uvm/firmware-bundles"),
    tenant_prefix_safe_read("/uvm/guest-profiles"),
    tenant_prefix_unsafe_async_mutate("/uvm/guest-profiles"),
    tenant_prefix_safe_read("/uvm/overlay-policies"),
    tenant_prefix_unsafe_async_mutate("/uvm/overlay-policies"),
    tenant_prefix_safe_read("/uvm/region-cell-policies"),
    tenant_prefix_unsafe_async_mutate("/uvm/region-cell-policies"),
    tenant_prefix_safe_read("/uvm/compatibility-matrix"),
    tenant_prefix_unsafe_async_mutate("/uvm/compatibility-matrix"),
    tenant_prefix_safe_read("/uvm/image-outbox"),
    tenant_prefix_unsafe_async_mutate("/uvm/image-outbox"),
];
const UVM_NODE_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    operator_exact_read("/uvm/node"),
    tenant_exact_read("/uvm/node-capabilities"),
    tenant_exact_unsafe_async_mutate("/uvm/node-capabilities"),
    operator_prefix_safe_read("/uvm/node-capabilities"),
    operator_prefix_unsafe_mutate("/uvm/node-capabilities"),
    operator_prefix_safe_read("/uvm/device-profiles"),
    operator_prefix_unsafe_mutate("/uvm/device-profiles"),
    operator_prefix_safe_read("/uvm/node-operations"),
    operator_prefix_unsafe_mutate("/uvm/node-operations"),
    operator_prefix_safe_read("/uvm/node-drains"),
    operator_prefix_unsafe_mutate("/uvm/node-drains"),
    tenant_exact_read("/uvm/runtime/preflight"),
    tenant_exact_unsafe_async_mutate("/uvm/runtime/preflight"),
    operator_prefix_safe_read("/uvm/runtime"),
    operator_prefix_unsafe_mutate("/uvm/runtime"),
    operator_prefix_safe_read("/uvm/node-outbox"),
    operator_prefix_unsafe_mutate("/uvm/node-outbox"),
];
const UVM_OBSERVE_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
    operator_exact_read("/uvm/observe"),
    operator_exact_read("/uvm/observe/summary"),
    operator_prefix_safe_read("/uvm/perf-attestations"),
    operator_prefix_unsafe_mutate("/uvm/perf-attestations"),
    operator_prefix_safe_read("/uvm/failure-reports"),
    operator_prefix_unsafe_mutate("/uvm/failure-reports"),
    operator_prefix_safe_read("/uvm/host-evidence"),
    operator_prefix_unsafe_mutate("/uvm/host-evidence"),
    operator_prefix_safe_read("/uvm/preflight-evidence-artifacts"),
    operator_prefix_unsafe_mutate("/uvm/preflight-evidence-artifacts"),
    operator_prefix_safe_read("/uvm/claim-decisions"),
    operator_prefix_unsafe_mutate("/uvm/claim-decisions"),
    operator_prefix_safe_read("/uvm/benchmark-campaigns"),
    operator_prefix_unsafe_mutate("/uvm/benchmark-campaigns"),
    operator_prefix_safe_read("/uvm/benchmark-baselines"),
    operator_prefix_unsafe_mutate("/uvm/benchmark-baselines"),
    operator_prefix_safe_read("/uvm/benchmark-results"),
    operator_prefix_unsafe_mutate("/uvm/benchmark-results"),
    operator_prefix_safe_read("/uvm/native-claim-status"),
    operator_prefix_unsafe_mutate("/uvm/native-claim-status"),
    operator_prefix_safe_read("/uvm/observe-outbox"),
    operator_prefix_unsafe_mutate("/uvm/observe-outbox"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RuntimeServiceKey {
    RuntimeOperator,
    RuntimeInternal,
    Console,
    Identity,
    Tenancy,
    Control,
    Container,
    Scheduler,
    Node,
    Ingress,
    Dns,
    Netsec,
    Storage,
    Data,
    Stream,
    Mail,
    Governance,
    Ha,
    Lifecycle,
    Secrets,
    Billing,
    Notify,
    Observe,
    Policy,
    Abuse,
    UvmControl,
    UvmImage,
    UvmNode,
    UvmObserve,
}

impl RuntimeServiceKey {
    pub(crate) const fn service_name(self) -> &'static str {
        match self {
            Self::RuntimeOperator => "runtime-operator",
            Self::RuntimeInternal => "runtime-internal",
            Self::Console => "console",
            Self::Identity => "identity",
            Self::Tenancy => "tenancy",
            Self::Control => "control",
            Self::Container => "container",
            Self::Scheduler => "scheduler",
            Self::Node => "node",
            Self::Ingress => "ingress",
            Self::Dns => "dns",
            Self::Netsec => "netsec",
            Self::Storage => "storage",
            Self::Data => "data",
            Self::Stream => "stream",
            Self::Mail => "mail",
            Self::Governance => "governance",
            Self::Ha => "ha",
            Self::Lifecycle => "lifecycle",
            Self::Secrets => "secrets",
            Self::Billing => "billing",
            Self::Notify => "notify",
            Self::Observe => "observe",
            Self::Policy => "policy",
            Self::Abuse => "abuse",
            Self::UvmControl => "uvm-control",
            Self::UvmImage => "uvm-image",
            Self::UvmNode => "uvm-node",
            Self::UvmObserve => "uvm-observe",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ServiceRouteSurfaceManifest {
    key: RuntimeServiceKey,
    pub(crate) route_surfaces: &'static [RouteSurfaceBinding],
    pub(crate) internal_route_audiences: &'static [InternalRouteAudienceBinding],
}

impl ServiceRouteSurfaceManifest {
    pub(crate) const fn service_name(&self) -> &'static str {
        self.key.service_name()
    }
}

pub(crate) const SERVICE_ROUTE_SURFACE_MANIFESTS: &[ServiceRouteSurfaceManifest] = &[
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Console,
        route_surfaces: CONSOLE_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::RuntimeOperator,
        route_surfaces: RUNTIME_OPERATOR_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::RuntimeInternal,
        route_surfaces: RUNTIME_INTERNAL_ROUTE_SURFACES,
        internal_route_audiences: RUNTIME_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Identity,
        route_surfaces: IDENTITY_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Tenancy,
        route_surfaces: TENANCY_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Control,
        route_surfaces: CONTROL_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Container,
        route_surfaces: CONTAINER_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Scheduler,
        route_surfaces: SCHEDULER_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Node,
        route_surfaces: NODE_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Ingress,
        route_surfaces: INGRESS_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Dns,
        route_surfaces: DNS_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Netsec,
        route_surfaces: NETSEC_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Storage,
        route_surfaces: STORAGE_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Data,
        route_surfaces: DATA_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Stream,
        route_surfaces: STREAM_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Mail,
        route_surfaces: MAIL_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Governance,
        route_surfaces: GOVERNANCE_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Ha,
        route_surfaces: HA_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Lifecycle,
        route_surfaces: LIFECYCLE_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Secrets,
        route_surfaces: SECRETS_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Billing,
        route_surfaces: BILLING_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Notify,
        route_surfaces: NOTIFY_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Observe,
        route_surfaces: OBSERVE_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Policy,
        route_surfaces: POLICY_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::Abuse,
        route_surfaces: ABUSE_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::UvmControl,
        route_surfaces: UVM_CONTROL_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::UvmImage,
        route_surfaces: UVM_IMAGE_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::UvmNode,
        route_surfaces: UVM_NODE_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
    ServiceRouteSurfaceManifest {
        key: RuntimeServiceKey::UvmObserve,
        route_surfaces: UVM_OBSERVE_ROUTE_SURFACES,
        internal_route_audiences: NO_INTERNAL_ROUTE_AUDIENCES,
    },
];

const EDGE_SERVICE_KEYS: &[RuntimeServiceKey] = &[
    RuntimeServiceKey::Console,
    RuntimeServiceKey::Dns,
    RuntimeServiceKey::Ingress,
];
const IDENTITY_AND_POLICY_SERVICE_KEYS: &[RuntimeServiceKey] = &[
    RuntimeServiceKey::Identity,
    RuntimeServiceKey::Tenancy,
    RuntimeServiceKey::Policy,
    RuntimeServiceKey::Secrets,
];
const CONTROL_SERVICE_KEYS: &[RuntimeServiceKey] = &[
    RuntimeServiceKey::Control,
    RuntimeServiceKey::Container,
    RuntimeServiceKey::Scheduler,
    RuntimeServiceKey::Node,
    RuntimeServiceKey::Ha,
    RuntimeServiceKey::Lifecycle,
];
const NODE_ADJACENT_CONTROL_SERVICE_KEYS: &[RuntimeServiceKey] = &[RuntimeServiceKey::Node];
const DATA_AND_MESSAGING_SERVICE_KEYS: &[RuntimeServiceKey] = &[
    RuntimeServiceKey::Netsec,
    RuntimeServiceKey::Storage,
    RuntimeServiceKey::Data,
    RuntimeServiceKey::Stream,
    RuntimeServiceKey::Mail,
];
const GOVERNANCE_AND_OPERATIONS_SERVICE_KEYS: &[RuntimeServiceKey] = &[
    RuntimeServiceKey::Governance,
    RuntimeServiceKey::Billing,
    RuntimeServiceKey::Notify,
    RuntimeServiceKey::Observe,
    RuntimeServiceKey::Abuse,
];
const UVM_SERVICE_KEYS: &[RuntimeServiceKey] = &[
    RuntimeServiceKey::UvmControl,
    RuntimeServiceKey::UvmImage,
    RuntimeServiceKey::UvmNode,
    RuntimeServiceKey::UvmObserve,
];
const NODE_ADJACENT_UVM_SERVICE_KEYS: &[RuntimeServiceKey] = &[RuntimeServiceKey::UvmNode];

#[derive(Debug, Clone, Copy)]
pub(crate) struct RuntimeServiceGroupManifest {
    pub(crate) group: RuntimeLogicalServiceGroup,
    services: &'static [RuntimeServiceKey],
}

impl RuntimeServiceGroupManifest {
    pub(crate) fn service_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.services
            .iter()
            .copied()
            .map(RuntimeServiceKey::service_name)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn sorted_service_name_refs(&self) -> Vec<&'static str> {
        let mut service_names = self.service_names().collect::<Vec<_>>();
        service_names.sort_unstable();
        service_names
    }

    async fn build_services(
        &self,
        context: &RuntimeServiceFactoryContext,
    ) -> Result<Vec<ActivatedRuntimeService>> {
        match self.group {
            RuntimeLogicalServiceGroup::Edge => build_edge_services(self.services, context).await,
            RuntimeLogicalServiceGroup::IdentityAndPolicy => {
                build_identity_and_policy_services(self.services, context).await
            }
            RuntimeLogicalServiceGroup::Control => {
                build_control_services(self.services, context).await
            }
            RuntimeLogicalServiceGroup::DataAndMessaging => {
                build_data_and_messaging_services(self.services, context).await
            }
            RuntimeLogicalServiceGroup::GovernanceAndOperations => {
                build_governance_and_operations_services(self.services, context).await
            }
            RuntimeLogicalServiceGroup::Uvm => build_uvm_services(self.services, context).await,
        }
    }

    #[cfg(test)]
    pub(crate) fn sorted_service_names(&self) -> Vec<String> {
        self.sorted_service_name_refs()
            .into_iter()
            .map(str::to_owned)
            .collect()
    }
}

const ALL_IN_ONE_RUNTIME_SERVICE_GROUP_MANIFESTS: &[RuntimeServiceGroupManifest] = &[
    RuntimeServiceGroupManifest {
        group: RuntimeLogicalServiceGroup::Edge,
        services: EDGE_SERVICE_KEYS,
    },
    RuntimeServiceGroupManifest {
        group: RuntimeLogicalServiceGroup::IdentityAndPolicy,
        services: IDENTITY_AND_POLICY_SERVICE_KEYS,
    },
    RuntimeServiceGroupManifest {
        group: RuntimeLogicalServiceGroup::Control,
        services: CONTROL_SERVICE_KEYS,
    },
    RuntimeServiceGroupManifest {
        group: RuntimeLogicalServiceGroup::DataAndMessaging,
        services: DATA_AND_MESSAGING_SERVICE_KEYS,
    },
    RuntimeServiceGroupManifest {
        group: RuntimeLogicalServiceGroup::GovernanceAndOperations,
        services: GOVERNANCE_AND_OPERATIONS_SERVICE_KEYS,
    },
    RuntimeServiceGroupManifest {
        group: RuntimeLogicalServiceGroup::Uvm,
        services: UVM_SERVICE_KEYS,
    },
];
const EDGE_RUNTIME_SERVICE_GROUP_MANIFESTS: &[RuntimeServiceGroupManifest] =
    &[RuntimeServiceGroupManifest {
        group: RuntimeLogicalServiceGroup::Edge,
        services: EDGE_SERVICE_KEYS,
    }];
const CONTROLLER_RUNTIME_SERVICE_GROUP_MANIFESTS: &[RuntimeServiceGroupManifest] = &[
    RuntimeServiceGroupManifest {
        group: RuntimeLogicalServiceGroup::IdentityAndPolicy,
        services: IDENTITY_AND_POLICY_SERVICE_KEYS,
    },
    RuntimeServiceGroupManifest {
        group: RuntimeLogicalServiceGroup::Control,
        services: CONTROL_SERVICE_KEYS,
    },
    RuntimeServiceGroupManifest {
        group: RuntimeLogicalServiceGroup::GovernanceAndOperations,
        services: GOVERNANCE_AND_OPERATIONS_SERVICE_KEYS,
    },
    RuntimeServiceGroupManifest {
        group: RuntimeLogicalServiceGroup::Uvm,
        services: UVM_SERVICE_KEYS,
    },
];
const WORKER_RUNTIME_SERVICE_GROUP_MANIFESTS: &[RuntimeServiceGroupManifest] =
    &[RuntimeServiceGroupManifest {
        group: RuntimeLogicalServiceGroup::DataAndMessaging,
        services: DATA_AND_MESSAGING_SERVICE_KEYS,
    }];
const NODE_ADJACENT_RUNTIME_SERVICE_GROUP_MANIFESTS: &[RuntimeServiceGroupManifest] = &[
    RuntimeServiceGroupManifest {
        group: RuntimeLogicalServiceGroup::Control,
        services: NODE_ADJACENT_CONTROL_SERVICE_KEYS,
    },
    RuntimeServiceGroupManifest {
        group: RuntimeLogicalServiceGroup::Uvm,
        services: NODE_ADJACENT_UVM_SERVICE_KEYS,
    },
];

#[derive(Debug, Clone, Copy)]
struct RuntimeRoleManifest {
    process_role: RuntimeProcessRole,
    service_groups: &'static [RuntimeServiceGroupManifest],
}

const RUNTIME_ROLE_MANIFESTS: &[RuntimeRoleManifest] = &[
    RuntimeRoleManifest {
        process_role: RuntimeProcessRole::AllInOne,
        service_groups: ALL_IN_ONE_RUNTIME_SERVICE_GROUP_MANIFESTS,
    },
    RuntimeRoleManifest {
        process_role: RuntimeProcessRole::Edge,
        service_groups: EDGE_RUNTIME_SERVICE_GROUP_MANIFESTS,
    },
    RuntimeRoleManifest {
        process_role: RuntimeProcessRole::Controller,
        service_groups: CONTROLLER_RUNTIME_SERVICE_GROUP_MANIFESTS,
    },
    RuntimeRoleManifest {
        process_role: RuntimeProcessRole::Worker,
        service_groups: WORKER_RUNTIME_SERVICE_GROUP_MANIFESTS,
    },
    RuntimeRoleManifest {
        process_role: RuntimeProcessRole::NodeAdjacent,
        service_groups: NODE_ADJACENT_RUNTIME_SERVICE_GROUP_MANIFESTS,
    },
];

fn runtime_role_manifest(process_role: RuntimeProcessRole) -> &'static RuntimeRoleManifest {
    RUNTIME_ROLE_MANIFESTS
        .iter()
        .find(|manifest| manifest.process_role == process_role)
        .unwrap_or_else(|| {
            panic!(
                "runtime process role `{}` is missing an activation manifest",
                process_role.as_str()
            )
        })
}

pub(crate) fn parse_runtime_process_role(value: &str) -> Option<RuntimeProcessRole> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    RUNTIME_ROLE_MANIFESTS
        .iter()
        .find(|manifest| manifest.process_role.as_str() == trimmed)
        .map(|manifest| manifest.process_role)
}

pub(crate) fn supported_runtime_process_role_names() -> impl Iterator<Item = &'static str> + Clone {
    RUNTIME_ROLE_MANIFESTS
        .iter()
        .map(|manifest| manifest.process_role.as_str())
}

#[cfg(test)]
pub(crate) fn supported_runtime_process_roles() -> impl Iterator<Item = RuntimeProcessRole> + Clone
{
    RUNTIME_ROLE_MANIFESTS
        .iter()
        .map(|manifest| manifest.process_role)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RuntimeRoleActivationPlan {
    process_role: RuntimeProcessRole,
    service_groups: &'static [RuntimeServiceGroupManifest],
}

impl RuntimeRoleActivationPlan {
    pub(crate) const fn service_groups(&self) -> &'static [RuntimeServiceGroupManifest] {
        self.service_groups
    }

    pub(crate) fn active_runtime_service_groups(&self) -> Vec<RuntimeLogicalServiceGroup> {
        self.service_groups
            .iter()
            .map(|manifest| manifest.group)
            .collect()
    }

    pub(crate) fn publication_plan(
        &self,
        deployment_mode: ServiceMode,
        node_name: impl Into<String>,
        region: RuntimeRegionMembership,
        cell: RuntimeCellMembership,
    ) -> RuntimeRolePublicationPlan {
        let node_name = node_name.into();
        RuntimeRolePublicationPlan {
            activation_plan: *self,
            deployment_mode,
            registration_key: runtime_registration_key(self.process_role, node_name.as_str()),
            node_name,
            region,
            cell,
        }
    }

    pub(crate) fn activated_service_keys(&self) -> Vec<RuntimeServiceKey> {
        let mut service_keys = Vec::new();
        for manifest in self.service_groups() {
            for service_key in manifest.services.iter().copied() {
                if !service_keys.contains(&service_key) {
                    service_keys.push(service_key);
                }
            }
        }
        service_keys
    }

    fn locally_owned_route_service_keys(&self) -> Vec<RuntimeServiceKey> {
        let mut service_keys = self.activated_service_keys();
        service_keys.push(RuntimeServiceKey::RuntimeOperator);
        service_keys.push(RuntimeServiceKey::RuntimeInternal);
        service_keys
    }

    fn forwardable_non_local_service_keys(&self) -> Vec<RuntimeServiceKey> {
        let locally_owned_service_keys = self.locally_owned_route_service_keys();
        let mut service_keys = Vec::new();
        for role_manifest in RUNTIME_ROLE_MANIFESTS {
            if role_manifest.process_role == self.process_role {
                continue;
            }
            for service_group in role_manifest.service_groups {
                for service_key in service_group.services.iter().copied() {
                    if locally_owned_service_keys.contains(&service_key)
                        || service_keys.contains(&service_key)
                    {
                        continue;
                    }
                    service_keys.push(service_key);
                }
            }
        }
        service_keys
    }

    fn service_endpoint_bindings(
        &self,
        listener_address: SocketAddr,
    ) -> Vec<ServiceEndpointBinding> {
        let listener_address = listener_address.to_string();
        let mut bindings = Vec::new();
        for manifest in self.service_groups() {
            let mut protocols = Vec::new();
            for service_key in manifest.services.iter().copied() {
                let route_surface_manifest = service_route_surface_manifest(service_key);
                for binding in route_surface_manifest.route_surfaces.iter().copied() {
                    let protocol = service_endpoint_protocol_for_route_surface(binding);
                    if !protocols.contains(&protocol) {
                        protocols.push(protocol);
                    }
                }
            }
            for protocol in protocols {
                bindings.push(ServiceEndpointBinding::new(
                    manifest.group.as_str(),
                    listener_address.clone(),
                    protocol,
                ));
            }
        }
        bindings
    }

    pub(crate) fn topology(
        &self,
        deployment_mode: ServiceMode,
        node_name: impl Into<String>,
        region: RuntimeRegionMembership,
        cell: RuntimeCellMembership,
    ) -> RuntimeTopology {
        let mut topology = RuntimeTopology::new(self.process_role)
            .with_deployment_mode(deployment_mode)
            .with_node_name(node_name)
            .with_region_membership(region)
            .with_cell_membership(cell);

        for manifest in self.service_groups() {
            topology = topology.with_service_group(
                manifest.group,
                self.process_role,
                manifest.service_names(),
            );
        }

        topology
    }

    pub(crate) async fn build_runtime_services(
        &self,
        context: &RuntimeServiceFactoryContext,
    ) -> Result<Vec<ServiceRegistration>> {
        let mut services =
            Vec::with_capacity(self.activated_service_keys().len().saturating_add(2));
        let (runtime_operator_key, runtime_operator_service) =
            build_runtime_operator_service(context);
        services.push(register_service_key(
            runtime_operator_key,
            runtime_operator_service,
        )?);
        let (runtime_internal_key, runtime_internal_service) =
            build_runtime_internal_service(context);
        services.push(register_service_key(
            runtime_internal_key,
            runtime_internal_service,
        )?);

        for manifest in self.service_groups() {
            for (service_key, service) in manifest.build_services(context).await? {
                services.push(register_service_key(service_key, service)?);
            }
        }

        Ok(services)
    }

    #[cfg(test)]
    pub(crate) fn activated_service_names(&self) -> Vec<&'static str> {
        let mut service_names = self
            .activated_service_keys()
            .into_iter()
            .map(RuntimeServiceKey::service_name)
            .collect::<Vec<_>>();
        service_names.sort_unstable();
        service_names
    }

    #[cfg(test)]
    pub(crate) async fn build_runtime_service_names(
        &self,
        context: &RuntimeServiceFactoryContext,
    ) -> Result<Vec<&'static str>> {
        let mut service_names =
            Vec::with_capacity(self.activated_service_keys().len().saturating_add(2));
        service_names.push(build_runtime_operator_service(context).1.name());
        service_names.push(build_runtime_internal_service(context).1.name());

        for manifest in self.service_groups() {
            for (_, service) in manifest.build_services(context).await? {
                service_names.push(service.name());
            }
        }

        service_names.sort_unstable();
        service_names.dedup();
        Ok(service_names)
    }

    #[cfg(test)]
    pub(crate) fn forwardable_non_local_service_names(&self) -> Vec<&'static str> {
        let mut service_names = self
            .forwardable_non_local_service_keys()
            .into_iter()
            .map(RuntimeServiceKey::service_name)
            .collect::<Vec<_>>();
        service_names.sort_unstable();
        service_names
    }

    fn cell_participant(
        &self,
        registration: &LeaseRegistrationRecord,
        node_name: &str,
        observed_at: OffsetDateTime,
    ) -> CellParticipantRecord {
        let mut participant = CellParticipantRecord::new(
            registration.registration_id.clone(),
            registration.subject_kind.clone(),
            registration.subject_id.clone(),
            registration.role.clone(),
        )
        .with_node_name(node_name)
        .with_service_groups(
            self.active_runtime_service_groups()
                .into_iter()
                .map(|group| group.as_str()),
        )
        .with_lease_registration_id(registration.registration_id.clone())
        .with_state(cell_participant_state_from_registration_at(
            registration,
            observed_at,
        ))
        .with_reconciliation(CellParticipantReconciliationState::new(observed_at));
        participant.registered_at = registration.registered_at;
        participant
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeRolePublicationPlan {
    activation_plan: RuntimeRoleActivationPlan,
    deployment_mode: ServiceMode,
    registration_key: String,
    node_name: String,
    region: RuntimeRegionMembership,
    cell: RuntimeCellMembership,
}

impl RuntimeRolePublicationPlan {
    pub(crate) const fn process_role(&self) -> RuntimeProcessRole {
        self.activation_plan.process_role
    }

    pub(crate) const fn owns_runtime_registry_reconciliation(&self) -> bool {
        match self.process_role() {
            RuntimeProcessRole::AllInOne | RuntimeProcessRole::Controller => true,
            RuntimeProcessRole::Edge
            | RuntimeProcessRole::Worker
            | RuntimeProcessRole::NodeAdjacent => false,
        }
    }

    pub(crate) fn registration_key(&self) -> &str {
        self.registration_key.as_str()
    }

    pub(crate) fn node_name(&self) -> &str {
        self.node_name.as_str()
    }

    pub(crate) fn region(&self) -> &RuntimeRegionMembership {
        &self.region
    }

    pub(crate) fn cell(&self) -> &RuntimeCellMembership {
        &self.cell
    }

    pub(crate) fn service_endpoint_bindings(
        &self,
        listener_address: SocketAddr,
    ) -> Vec<ServiceEndpointBinding> {
        self.activation_plan
            .service_endpoint_bindings(listener_address)
    }

    pub(crate) fn forwarded_service_registrations<'a, I>(
        &self,
        service_names: I,
    ) -> Result<Vec<ForwardedServiceRegistration>>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let local_service_keys = self.activation_plan.locally_owned_route_service_keys();
        let forwardable_non_local_service_keys =
            self.activation_plan.forwardable_non_local_service_keys();

        let mut registrations: Vec<ForwardedServiceRegistration> = Vec::new();
        for service_name in service_names {
            let service_name = service_name.trim();
            if service_name.is_empty() {
                return Err(PlatformError::invalid(
                    "runtime.forward_targets keys may not be empty",
                ));
            }

            let manifest = service_route_surface_manifest_by_name(service_name)?;
            if local_service_keys.contains(&manifest.key) {
                return Err(PlatformError::invalid(format!(
                    "runtime.forward_targets may not target locally activated service `{service_name}`"
                )));
            }
            if !forwardable_non_local_service_keys.contains(&manifest.key) {
                return Err(PlatformError::invalid(format!(
                    "runtime.forward_targets may only target service families owned by another activation manifest; `{service_name}` is not owned by a non-local runtime role"
                )));
            }

            if registrations
                .iter()
                .any(|registration| registration.service_name() == manifest.service_name())
            {
                continue;
            }

            registrations.push(ForwardedServiceRegistration::new(
                manifest.service_name(),
                manifest.route_surfaces,
            ));
        }

        Ok(registrations)
    }

    pub(crate) fn topology_seed(&self) -> RuntimeTopology {
        self.activation_plan.topology(
            self.deployment_mode,
            self.node_name.clone(),
            self.region.clone(),
            self.cell.clone(),
        )
    }

    pub(crate) fn cell_participant(
        &self,
        registration: &LeaseRegistrationRecord,
        observed_at: OffsetDateTime,
    ) -> CellParticipantRecord {
        self.activation_plan
            .cell_participant(registration, self.node_name.as_str(), observed_at)
    }

    pub(crate) fn publish_topology(
        &self,
        registration: &LeaseRegistrationRecord,
        cell_directory: &CellDirectoryRecord,
        service_group_directory: &CellServiceGroupDirectoryRecord,
        cleanup_workflows: &BTreeMap<
            String,
            WorkflowInstance<StaleParticipantCleanupWorkflowState>,
        >,
        tombstone_history: &[ParticipantTombstoneHistoryRecord],
        observed_at: OffsetDateTime,
    ) -> RuntimeTopology {
        runtime_topology_with_cell_directory(
            self.topology_seed(),
            cell_directory,
            service_group_directory,
            cleanup_workflows,
            tombstone_history,
        )
        .with_process_state(runtime_process_state_from_registration_at(
            registration,
            observed_at,
        ))
    }

    pub(crate) async fn build_runtime_services(
        &self,
        context: &RuntimeServiceFactoryContext,
    ) -> Result<Vec<ServiceRegistration>> {
        self.activation_plan.build_runtime_services(context).await
    }

    #[cfg(test)]
    pub(crate) async fn build_runtime_service_names(
        &self,
        context: &RuntimeServiceFactoryContext,
    ) -> Result<Vec<&'static str>> {
        self.activation_plan
            .build_runtime_service_names(context)
            .await
    }
}

fn service_endpoint_protocol_for_route_surface(
    _binding: RouteSurfaceBinding,
) -> ServiceEndpointProtocol {
    // The runtime route catalog is currently served by the shared Hyper HTTP/1 listener.
    ServiceEndpointProtocol::Http
}

pub(crate) fn runtime_role_activation_plan(
    process_role: RuntimeProcessRole,
) -> RuntimeRoleActivationPlan {
    let manifest = runtime_role_manifest(process_role);
    RuntimeRoleActivationPlan {
        process_role: manifest.process_role,
        service_groups: manifest.service_groups,
    }
}

pub(crate) fn runtime_registration_key(
    process_role: RuntimeProcessRole,
    node_name: &str,
) -> String {
    format!("{}:{node_name}", process_role.as_str())
}

pub(crate) fn runtime_role_publication_plan(
    config: &AllInOneConfig,
) -> Result<RuntimeRolePublicationPlan> {
    let placement = config.runtime_cell_placement()?;
    let node_name = config.schema.node_name.trim().to_owned();
    Ok(
        runtime_role_activation_plan(config.runtime_process_role()?).publication_plan(
            config.schema.mode,
            node_name,
            placement.region_membership(),
            placement.cell_membership(),
        ),
    )
}

#[cfg(test)]
pub(crate) fn runtime_topology(config: &AllInOneConfig) -> Result<RuntimeTopology> {
    Ok(runtime_role_publication_plan(config)?.topology_seed())
}

#[cfg_attr(not(test), allow(dead_code))]
mod deployment_descriptors {
    use serde::Serialize;

    use super::{
        InternalRouteAudienceBinding, RUNTIME_ROLE_MANIFESTS, RouteSurfaceBinding,
        RuntimeLogicalServiceGroup, RuntimeProcessRole, RuntimeRoleActivationPlan,
        RuntimeServiceGroupManifest, RuntimeServiceKey, SERVICE_ROUTE_SURFACE_MANIFESTS,
        runtime_role_activation_plan,
    };

    const SCHEMA_VERSION: u32 = 1;
    const RUNTIME_LOCAL_SERVICE_KEYS: &[RuntimeServiceKey] = &[
        RuntimeServiceKey::RuntimeInternal,
        RuntimeServiceKey::RuntimeOperator,
    ];

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    pub(super) struct ActivationDeploymentDescriptorCatalog {
        schema_version: u32,
        service_catalog: Vec<ServiceDeploymentDescriptor>,
        deployment_descriptors: Vec<RuntimeDeploymentDescriptor>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct ServiceDeploymentDescriptor {
        service_name: &'static str,
        owner_process_roles: Vec<RuntimeProcessRole>,
        route_surfaces: Vec<RouteSurfaceDescriptor>,
        internal_route_audiences: Vec<InternalRouteAudienceDescriptor>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct RouteSurfaceDescriptor {
        claim: &'static str,
        match_kind: &'static str,
        surface: &'static str,
        method_match: &'static str,
        request_class: &'static str,
    }

    impl From<RouteSurfaceBinding> for RouteSurfaceDescriptor {
        fn from(binding: RouteSurfaceBinding) -> Self {
            Self {
                claim: binding.path(),
                match_kind: binding.match_kind(),
                surface: binding.surface().as_str(),
                method_match: binding.method_match().as_str(),
                request_class: binding.request_class().as_str(),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct InternalRouteAudienceDescriptor {
        claim: &'static str,
        match_kind: &'static str,
        audience: &'static str,
    }

    impl From<InternalRouteAudienceBinding> for InternalRouteAudienceDescriptor {
        fn from(binding: InternalRouteAudienceBinding) -> Self {
            Self {
                claim: binding.path(),
                match_kind: binding.match_kind(),
                audience: binding.audience(),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct RuntimeDeploymentDescriptor {
        process_role: RuntimeProcessRole,
        activated_service_names: Vec<&'static str>,
        service_groups: Vec<ServiceGroupDeploymentDescriptor>,
        forwardable_non_local_service_names: Vec<&'static str>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct ServiceGroupDeploymentDescriptor {
        group: RuntimeLogicalServiceGroup,
        services: Vec<&'static str>,
    }

    pub(super) fn catalog() -> ActivationDeploymentDescriptorCatalog {
        ActivationDeploymentDescriptorCatalog {
            schema_version: SCHEMA_VERSION,
            service_catalog: service_catalog(),
            deployment_descriptors: RUNTIME_ROLE_MANIFESTS
                .iter()
                .map(|manifest| runtime_deployment_descriptor(manifest.process_role))
                .collect(),
        }
    }

    fn service_catalog() -> Vec<ServiceDeploymentDescriptor> {
        let mut descriptors = SERVICE_ROUTE_SURFACE_MANIFESTS
            .iter()
            .map(|manifest| ServiceDeploymentDescriptor {
                service_name: manifest.service_name(),
                owner_process_roles: owner_process_roles_for_service(manifest.key),
                route_surfaces: manifest
                    .route_surfaces
                    .iter()
                    .copied()
                    .map(RouteSurfaceDescriptor::from)
                    .collect(),
                internal_route_audiences: manifest
                    .internal_route_audiences
                    .iter()
                    .copied()
                    .map(InternalRouteAudienceDescriptor::from)
                    .collect(),
            })
            .collect::<Vec<_>>();
        descriptors.sort_unstable_by_key(|descriptor| descriptor.service_name);
        descriptors
    }

    fn owner_process_roles_for_service(service_key: RuntimeServiceKey) -> Vec<RuntimeProcessRole> {
        if RUNTIME_LOCAL_SERVICE_KEYS.contains(&service_key) {
            return RUNTIME_ROLE_MANIFESTS
                .iter()
                .map(|manifest| manifest.process_role)
                .collect();
        }

        RUNTIME_ROLE_MANIFESTS
            .iter()
            .filter(|manifest| {
                manifest
                    .service_groups
                    .iter()
                    .any(|group| group.services.contains(&service_key))
            })
            .map(|manifest| manifest.process_role)
            .collect()
    }

    fn runtime_deployment_descriptor(
        process_role: RuntimeProcessRole,
    ) -> RuntimeDeploymentDescriptor {
        let activation_plan = runtime_role_activation_plan(process_role);
        RuntimeDeploymentDescriptor {
            process_role,
            activated_service_names: activated_service_names(&activation_plan),
            service_groups: activation_plan
                .service_groups()
                .iter()
                .map(service_group_descriptor)
                .collect(),
            forwardable_non_local_service_names: sorted_service_names(
                activation_plan.forwardable_non_local_service_keys(),
            ),
        }
    }

    fn service_group_descriptor(
        manifest: &RuntimeServiceGroupManifest,
    ) -> ServiceGroupDeploymentDescriptor {
        ServiceGroupDeploymentDescriptor {
            group: manifest.group,
            services: manifest.sorted_service_name_refs(),
        }
    }

    fn activated_service_names(activation_plan: &RuntimeRoleActivationPlan) -> Vec<&'static str> {
        let mut service_keys = activation_plan.activated_service_keys();
        service_keys.extend(RUNTIME_LOCAL_SERVICE_KEYS.iter().copied());
        sorted_service_names(service_keys)
    }

    fn sorted_service_names<I>(service_keys: I) -> Vec<&'static str>
    where
        I: IntoIterator<Item = RuntimeServiceKey>,
    {
        let mut service_names = service_keys
            .into_iter()
            .map(RuntimeServiceKey::service_name)
            .collect::<Vec<_>>();
        service_names.sort_unstable();
        service_names.dedup();
        service_names
    }
}

fn runtime_readiness_state(readiness: LeaseReadiness) -> RuntimeReadinessState {
    match readiness {
        LeaseReadiness::Starting => RuntimeReadinessState::Starting,
        LeaseReadiness::Ready => RuntimeReadinessState::Ready,
    }
}

fn runtime_drain_intent(drain_intent: LeaseDrainIntent) -> RuntimeDrainIntent {
    match drain_intent {
        LeaseDrainIntent::Serving => RuntimeDrainIntent::Serving,
        LeaseDrainIntent::Draining => RuntimeDrainIntent::Draining,
    }
}

fn runtime_lease_freshness(freshness: LeaseFreshness) -> RuntimeLeaseFreshness {
    match freshness {
        LeaseFreshness::Fresh => RuntimeLeaseFreshness::Fresh,
        LeaseFreshness::Stale => RuntimeLeaseFreshness::Stale,
        LeaseFreshness::Expired => RuntimeLeaseFreshness::Expired,
    }
}

fn runtime_participant_lease_source(
    source: CellParticipantLeaseSource,
) -> RuntimeParticipantLeaseSource {
    match source {
        CellParticipantLeaseSource::LinkedRegistration => {
            RuntimeParticipantLeaseSource::LinkedRegistration
        }
        CellParticipantLeaseSource::PublishedStateFallback => {
            RuntimeParticipantLeaseSource::PublishedStateFallback
        }
    }
}

fn runtime_participant_degraded_reason(
    reason: CellParticipantDegradedReason,
) -> RuntimeParticipantDegradedReason {
    match reason {
        CellParticipantDegradedReason::LeaseStale => RuntimeParticipantDegradedReason::LeaseStale,
        CellParticipantDegradedReason::LeaseExpired => {
            RuntimeParticipantDegradedReason::LeaseExpired
        }
    }
}

fn runtime_participant_drain_phase(
    drain_phase: CellParticipantDrainPhase,
) -> RuntimeParticipantDrainPhase {
    match drain_phase {
        CellParticipantDrainPhase::Serving => RuntimeParticipantDrainPhase::Serving,
        CellParticipantDrainPhase::TakeoverPending => RuntimeParticipantDrainPhase::TakeoverPending,
        CellParticipantDrainPhase::TakeoverAcknowledged => {
            RuntimeParticipantDrainPhase::TakeoverAcknowledged
        }
    }
}

fn runtime_lease_state(
    renewed_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    duration_seconds: u32,
    freshness: LeaseFreshness,
) -> RuntimeLeaseState {
    RuntimeLeaseState::new(
        renewed_at,
        expires_at,
        duration_seconds,
        runtime_lease_freshness(freshness),
    )
}

fn runtime_process_state_from_registration_at(
    registration: &LeaseRegistrationRecord,
    observed_at: OffsetDateTime,
) -> RuntimeProcessState {
    RuntimeProcessState::new(
        registration.registration_id.clone(),
        runtime_readiness_state(registration.readiness),
        runtime_drain_intent(registration.drain_intent),
        registration.registered_at,
        runtime_lease_state(
            registration.lease_renewed_at,
            registration.lease_expires_at,
            registration.lease_duration_seconds,
            registration.lease_freshness_at(observed_at),
        ),
    )
}

fn cell_participant_state_from_registration_at(
    registration: &LeaseRegistrationRecord,
    observed_at: OffsetDateTime,
) -> CellParticipantState {
    CellParticipantState::new(
        registration.readiness,
        registration.drain_intent,
        CellParticipantLeaseState::new(
            registration.lease_renewed_at,
            registration.lease_expires_at,
            registration.lease_duration_seconds,
            registration.lease_freshness_at(observed_at),
        ),
    )
    .with_lease_source(CellParticipantLeaseSource::LinkedRegistration)
}

fn runtime_participant_state_from_cell_directory(
    state: &CellParticipantState,
) -> RuntimeParticipantState {
    let mut runtime_state = RuntimeParticipantState::new(
        runtime_readiness_state(state.readiness),
        runtime_drain_intent(state.drain_intent),
        runtime_lease_state(
            state.lease.renewed_at,
            state.lease.expires_at,
            state.lease.duration_seconds,
            state.lease.freshness,
        ),
    )
    .with_published_drain_intent(runtime_drain_intent(state.published_drain_intent()))
    .with_lease_source(runtime_participant_lease_source(state.lease_source));
    if let (Some(takeover_registration_id), Some(takeover_acknowledged_at)) = (
        state.takeover_registration_id.clone(),
        state.takeover_acknowledged_at,
    ) {
        runtime_state = runtime_state
            .with_takeover_acknowledgement(takeover_registration_id, takeover_acknowledged_at);
    }
    runtime_state.drain_phase = runtime_participant_drain_phase(state.drain_phase);
    runtime_state
}

fn runtime_service_group_conflict_state(
    conflict_state: CellServiceGroupConflictState,
) -> RuntimeServiceGroupConflictState {
    match conflict_state {
        CellServiceGroupConflictState::NoConflict => RuntimeServiceGroupConflictState::NoConflict,
        CellServiceGroupConflictState::MultipleHealthyRegistrations => {
            RuntimeServiceGroupConflictState::MultipleHealthyRegistrations
        }
    }
}

fn runtime_service_group_registration_resolution_from_store(
    registration: &CellServiceGroupRegistrationResolution,
) -> RuntimeServiceGroupRegistrationResolution {
    let mut runtime_registration = RuntimeServiceGroupRegistrationResolution::new(
        registration.registration_id.clone(),
        registration.participant_kind.clone(),
        registration.subject_id.clone(),
        registration.role.clone(),
        registration.registered_at,
        registration.healthy,
    );
    if let Some(node_name) = registration.node_name.clone() {
        runtime_registration = runtime_registration.with_node_name(node_name);
    }
    if let Some(lease_registration_id) = registration.lease_registration_id.clone() {
        runtime_registration =
            runtime_registration.with_lease_registration_id(lease_registration_id);
    }
    if let Some(readiness) = registration.readiness {
        runtime_registration =
            runtime_registration.with_readiness(runtime_readiness_state(readiness));
    }
    if let Some(drain_intent) = registration.drain_intent {
        runtime_registration =
            runtime_registration.with_drain_intent(runtime_drain_intent(drain_intent));
    }
    if let Some(drain_phase) = registration.drain_phase {
        runtime_registration =
            runtime_registration.with_drain_phase(runtime_participant_drain_phase(drain_phase));
    }
    if let (Some(takeover_registration_id), Some(takeover_acknowledged_at)) = (
        registration.takeover_registration_id.clone(),
        registration.takeover_acknowledged_at,
    ) {
        runtime_registration = runtime_registration
            .with_takeover_acknowledgement(takeover_registration_id, takeover_acknowledged_at);
    }
    if let Some(lease_freshness) = registration.lease_freshness {
        runtime_registration =
            runtime_registration.with_lease_freshness(runtime_lease_freshness(lease_freshness));
    }
    runtime_registration
}

fn runtime_service_group_directory_entry_from_store(
    entry: &CellServiceGroupDirectoryEntry,
) -> Option<RuntimeServiceGroupDirectoryEntry> {
    let group = RuntimeLogicalServiceGroup::parse(entry.group.as_str())?;
    Some(
        RuntimeServiceGroupDirectoryEntry::new(group)
            .with_resolved_registration_ids(entry.resolved_registration_ids.iter().cloned())
            .with_conflict_state(runtime_service_group_conflict_state(entry.conflict_state))
            .with_registrations(
                entry
                    .registrations
                    .iter()
                    .map(runtime_service_group_registration_resolution_from_store),
            ),
    )
}

fn runtime_workflow_phase(phase: WorkflowPhase) -> &'static str {
    match phase {
        WorkflowPhase::Pending => "pending",
        WorkflowPhase::Running => "running",
        WorkflowPhase::Paused => "paused",
        WorkflowPhase::Completed => "completed",
        WorkflowPhase::Failed => "failed",
        WorkflowPhase::RolledBack => "rolled_back",
    }
}

fn runtime_participant_cleanup_stage(
    stage: StaleParticipantCleanupStage,
) -> RuntimeParticipantCleanupStage {
    match stage {
        StaleParticipantCleanupStage::PendingReview => {
            RuntimeParticipantCleanupStage::PendingReview
        }
        StaleParticipantCleanupStage::PreflightConfirmed => {
            RuntimeParticipantCleanupStage::PreflightConfirmed
        }
        StaleParticipantCleanupStage::TombstoneEligible => {
            RuntimeParticipantCleanupStage::TombstoneEligible
        }
    }
}

fn runtime_participant_cleanup_workflow_from_store(
    workflow: &WorkflowInstance<StaleParticipantCleanupWorkflowState>,
) -> RuntimeParticipantCleanupWorkflow {
    let mut runtime_workflow = RuntimeParticipantCleanupWorkflow::new(
        workflow.id.clone(),
        workflow.workflow_kind.clone(),
        runtime_workflow_phase(workflow.phase.clone()),
        runtime_participant_cleanup_stage(workflow.state.stage),
        workflow.state.review_observations,
        workflow.state.last_observed_stale_at,
        workflow.created_at,
        workflow.updated_at,
    );
    if let Some(preflight_confirmed_at) = workflow.state.preflight_confirmed_at {
        runtime_workflow = runtime_workflow.with_preflight_confirmed_at(preflight_confirmed_at);
    }
    if let Some(route_withdrawal) = workflow.state.route_withdrawal.as_ref() {
        runtime_workflow =
            runtime_workflow.with_route_withdrawal(RuntimeEvacuationRouteWithdrawalArtifact::new(
                route_withdrawal.artifact_id.clone(),
                route_withdrawal.source_participant_registration_id.clone(),
                route_withdrawal.service_groups.clone(),
                route_withdrawal.prepared_at,
            ));
    }
    if let Some(target_readiness) = workflow.state.target_readiness.as_ref() {
        runtime_workflow =
            runtime_workflow.with_target_readiness(RuntimeEvacuationTargetReadinessArtifact::new(
                target_readiness.artifact_id.clone(),
                target_readiness.source_participant_registration_id.clone(),
                target_readiness.target_participant_registration_id.clone(),
                target_readiness.service_groups.clone(),
                target_readiness.prepared_at,
            ));
    }
    if let Some(rollback) = workflow.state.rollback.as_ref() {
        runtime_workflow = runtime_workflow.with_rollback(RuntimeEvacuationRollbackArtifact::new(
            rollback.artifact_id.clone(),
            rollback.source_participant_registration_id.clone(),
            rollback.target_participant_registration_id.clone(),
            rollback.service_groups.clone(),
            rollback.prepared_at,
        ));
    }
    if let Some(tombstone_eligible_at) = workflow.state.tombstone_eligible_at {
        runtime_workflow = runtime_workflow.with_tombstone_eligible_at(tombstone_eligible_at);
    }
    runtime_workflow
}

fn runtime_participant_reconciliation_from_cell_directory(
    participant: &CellParticipantRecord,
    cleanup_workflows: &BTreeMap<String, WorkflowInstance<StaleParticipantCleanupWorkflowState>>,
) -> Option<RuntimeParticipantReconciliation> {
    let reconciliation = participant.reconciliation.as_ref()?;
    let mut runtime_reconciliation =
        RuntimeParticipantReconciliation::new(reconciliation.last_reconciled_at);
    if let Some(stale_since) = reconciliation.stale_since {
        runtime_reconciliation = runtime_reconciliation.with_stale_since(stale_since);
    }
    if let Some(cleanup_workflow_id) = reconciliation.cleanup_workflow_id.as_deref()
        && let Some(workflow) = cleanup_workflows.get(cleanup_workflow_id)
    {
        runtime_reconciliation = runtime_reconciliation
            .with_cleanup_workflow(runtime_participant_cleanup_workflow_from_store(workflow));
    }
    Some(runtime_reconciliation)
}

fn runtime_participant_from_cell_directory(
    participant: &CellParticipantRecord,
    cleanup_workflows: &BTreeMap<String, WorkflowInstance<StaleParticipantCleanupWorkflowState>>,
) -> RuntimeParticipantRegistration {
    let mut runtime_participant = RuntimeParticipantRegistration::new(
        participant.registration_id.clone(),
        participant.participant_kind.clone(),
        participant.subject_id.clone(),
        participant.role.clone(),
        participant.registered_at,
    )
    .with_service_groups(participant.service_groups.iter().cloned());
    if let Some(node_name) = participant.node_name.clone() {
        runtime_participant = runtime_participant.with_node_name(node_name);
    }
    if let Some(lease_registration_id) = participant.lease_registration_id.clone() {
        runtime_participant = runtime_participant.with_lease_registration_id(lease_registration_id);
    }
    if let Some(state) = participant.state.as_ref() {
        runtime_participant =
            runtime_participant.with_state(runtime_participant_state_from_cell_directory(state));
    }
    if let Some(reconciliation) =
        runtime_participant_reconciliation_from_cell_directory(participant, cleanup_workflows)
    {
        runtime_participant = runtime_participant.with_reconciliation(reconciliation);
    }
    runtime_participant
}

pub(crate) fn runtime_participant_tombstone_history_entry_from_record(
    record: &ParticipantTombstoneHistoryRecord,
) -> RuntimeParticipantTombstoneHistoryEntry {
    RuntimeParticipantTombstoneHistoryEntry {
        event_id: record.event_id.clone(),
        cell_id: record.cell_id.clone(),
        cell_name: record.cell_name.clone(),
        region_id: record.region_id.clone(),
        region_name: record.region_name.clone(),
        participant_registration_id: record.participant_registration_id.clone(),
        participant_kind: record.participant_kind.clone(),
        participant_subject_id: record.participant_subject_id.clone(),
        participant_role: record.participant_role.clone(),
        node_name: record.node_name.clone(),
        service_groups: record.service_groups.clone(),
        cleanup_workflow_id: record.cleanup_workflow_id.clone(),
        review_observations: record.review_observations,
        stale_since: record.stale_since,
        preflight_confirmed_at: record.preflight_confirmed_at,
        tombstone_eligible_at: record.tombstone_eligible_at,
        tombstoned_at: record.tombstoned_at,
        actor_subject: record.actor_subject.clone(),
        actor_type: record.actor_type.clone(),
        correlation_id: record.correlation_id.clone(),
        lease_registration_id: record.lease_registration_id.clone(),
        published_drain_intent: record.published_drain_intent.map(runtime_drain_intent),
        degraded_reason: record
            .degraded_reason
            .map(runtime_participant_degraded_reason),
        lease_source: record.lease_source.map(runtime_participant_lease_source),
        removed_from_cell_directory: record.removed_from_cell_directory,
        lease_registration_soft_deleted: record.lease_registration_soft_deleted,
        cleanup_workflow_soft_deleted: record.cleanup_workflow_soft_deleted,
    }
}

fn runtime_topology_with_cell_directory(
    topology: RuntimeTopology,
    cell_directory: &CellDirectoryRecord,
    service_group_directory: &CellServiceGroupDirectoryRecord,
    cleanup_workflows: &BTreeMap<String, WorkflowInstance<StaleParticipantCleanupWorkflowState>>,
    tombstone_history: &[ParticipantTombstoneHistoryRecord],
) -> RuntimeTopology {
    topology
        .with_region_membership(RuntimeRegionMembership::new(
            cell_directory.region.region_id.clone(),
            cell_directory.region.region_name.clone(),
        ))
        .with_cell_membership(RuntimeCellMembership::new(
            cell_directory.cell_id.clone(),
            cell_directory.cell_name.clone(),
        ))
        .with_service_group_directory(
            service_group_directory
                .groups
                .iter()
                .filter_map(runtime_service_group_directory_entry_from_store),
        )
        .with_participants(cell_directory.participants.iter().map(|participant| {
            runtime_participant_from_cell_directory(participant, cleanup_workflows)
        }))
        .with_tombstone_history(
            tombstone_history
                .iter()
                .filter(|entry| entry.cell_id == cell_directory.cell_id)
                .take(RUNTIME_TOMBSTONE_HISTORY_LIMIT)
                .map(runtime_participant_tombstone_history_entry_from_record),
        )
}

fn service_route_surface_manifest(
    service_key: RuntimeServiceKey,
) -> &'static ServiceRouteSurfaceManifest {
    SERVICE_ROUTE_SURFACE_MANIFESTS
        .iter()
        .find(|manifest| manifest.key == service_key)
        .unwrap_or_else(|| {
            panic!(
                "service `{}` is missing a runtime surface manifest",
                service_key.service_name()
            )
        })
}

fn service_route_surface_manifest_by_name(
    service_name: &str,
) -> Result<&'static ServiceRouteSurfaceManifest> {
    SERVICE_ROUTE_SURFACE_MANIFESTS
        .iter()
        .find(|manifest| manifest.service_name() == service_name)
        .ok_or_else(|| {
            PlatformError::invalid(format!(
                "service `{service_name}` is missing a runtime surface manifest"
            ))
        })
}

#[cfg(test)]
pub(crate) fn route_surfaces_for_service(
    service_name: &str,
) -> Result<&'static [RouteSurfaceBinding]> {
    service_route_surface_manifest_by_name(service_name).map(|manifest| manifest.route_surfaces)
}

fn register_service_key(
    service_key: RuntimeServiceKey,
    service: Arc<dyn HttpService>,
) -> Result<ServiceRegistration> {
    let manifest = service_route_surface_manifest(service_key);
    let actual_service_name = service.name();
    if actual_service_name != manifest.service_name() {
        return Err(PlatformError::invalid(format!(
            "runtime service activation for `{}` produced unexpected service `{actual_service_name}`",
            manifest.service_name()
        )));
    }
    Ok(ServiceRegistration::new_with_internal_route_audiences(
        service,
        manifest.route_surfaces,
        manifest.internal_route_audiences,
    ))
}

type ActivatedRuntimeService = (RuntimeServiceKey, Arc<dyn HttpService>);

#[derive(Clone)]
pub(crate) struct RuntimeServiceFactoryContext {
    state_dir: PathBuf,
    secrets_key: SecretBytes,
    identity_service: Arc<IdentityService>,
    registration_context: RuntimeProcessRegistrationContext,
}

impl RuntimeServiceFactoryContext {
    pub(crate) fn new(
        state_dir: PathBuf,
        secrets_key: SecretBytes,
        identity_service: Arc<IdentityService>,
        registration_context: RuntimeProcessRegistrationContext,
    ) -> Self {
        Self {
            state_dir,
            secrets_key,
            identity_service,
            registration_context,
        }
    }
}

fn build_runtime_operator_service(
    context: &RuntimeServiceFactoryContext,
) -> ActivatedRuntimeService {
    (
        RuntimeServiceKey::RuntimeOperator,
        Arc::new(RuntimeOperatorService::new(
            context.registration_context.clone(),
        )),
    )
}

fn build_runtime_internal_service(
    context: &RuntimeServiceFactoryContext,
) -> ActivatedRuntimeService {
    (
        RuntimeServiceKey::RuntimeInternal,
        Arc::new(RuntimeInternalService::new(
            context.registration_context.clone(),
        )),
    )
}

fn existing_runtime_service(
    service_key: RuntimeServiceKey,
    service: Arc<dyn HttpService>,
) -> ActivatedRuntimeService {
    (service_key, service)
}

async fn open_runtime_service<S, Fut>(
    service_key: RuntimeServiceKey,
    open: Fut,
) -> Result<ActivatedRuntimeService>
where
    S: HttpService + 'static,
    Fut: Future<Output = Result<S>>,
{
    let service: Arc<dyn HttpService> = Arc::new(open.await?);
    Ok((service_key, service))
}

fn unexpected_runtime_group_service(
    group: RuntimeLogicalServiceGroup,
    service_key: RuntimeServiceKey,
) -> PlatformError {
    PlatformError::invalid(format!(
        "runtime activation group `{}` does not own service `{}`",
        group.as_str(),
        service_key.service_name()
    ))
}

async fn build_edge_services(
    service_keys: &[RuntimeServiceKey],
    context: &RuntimeServiceFactoryContext,
) -> Result<Vec<ActivatedRuntimeService>> {
    let mut services = Vec::with_capacity(service_keys.len());
    for service_key in service_keys.iter().copied() {
        let service = match service_key {
            RuntimeServiceKey::Console => {
                open_runtime_service(service_key, ConsoleService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Dns => {
                open_runtime_service(service_key, DnsService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Ingress => {
                open_runtime_service(service_key, IngressService::open(&context.state_dir)).await
            }
            unexpected => Err(unexpected_runtime_group_service(
                RuntimeLogicalServiceGroup::Edge,
                unexpected,
            )),
        }?;
        services.push(service);
    }
    Ok(services)
}

async fn build_identity_and_policy_services(
    service_keys: &[RuntimeServiceKey],
    context: &RuntimeServiceFactoryContext,
) -> Result<Vec<ActivatedRuntimeService>> {
    let mut services = Vec::with_capacity(service_keys.len());
    for service_key in service_keys.iter().copied() {
        let service = match service_key {
            RuntimeServiceKey::Identity => Ok(existing_runtime_service(
                service_key,
                context.identity_service.clone(),
            )),
            RuntimeServiceKey::Tenancy => {
                open_runtime_service(service_key, TenancyService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Policy => {
                open_runtime_service(service_key, PolicyService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Secrets => {
                open_runtime_service(
                    service_key,
                    SecretsService::open(&context.state_dir, context.secrets_key.clone()),
                )
                .await
            }
            unexpected => Err(unexpected_runtime_group_service(
                RuntimeLogicalServiceGroup::IdentityAndPolicy,
                unexpected,
            )),
        }?;
        services.push(service);
    }
    Ok(services)
}

async fn build_control_services(
    service_keys: &[RuntimeServiceKey],
    context: &RuntimeServiceFactoryContext,
) -> Result<Vec<ActivatedRuntimeService>> {
    let mut services = Vec::with_capacity(service_keys.len());
    for service_key in service_keys.iter().copied() {
        let service = match service_key {
            RuntimeServiceKey::Control => {
                open_runtime_service(service_key, ControlService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Container => {
                open_runtime_service(service_key, ContainerService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Scheduler => {
                open_runtime_service(service_key, SchedulerService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Node => {
                open_runtime_service(service_key, NodeService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Ha => {
                open_runtime_service(service_key, HaService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Lifecycle => {
                open_runtime_service(service_key, LifecycleService::open(&context.state_dir)).await
            }
            unexpected => Err(unexpected_runtime_group_service(
                RuntimeLogicalServiceGroup::Control,
                unexpected,
            )),
        }?;
        services.push(service);
    }
    Ok(services)
}

async fn build_data_and_messaging_services(
    service_keys: &[RuntimeServiceKey],
    context: &RuntimeServiceFactoryContext,
) -> Result<Vec<ActivatedRuntimeService>> {
    let mut services = Vec::with_capacity(service_keys.len());
    for service_key in service_keys.iter().copied() {
        let service = match service_key {
            RuntimeServiceKey::Netsec => {
                open_runtime_service(service_key, NetsecService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Storage => {
                open_runtime_service(service_key, StorageService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Data => {
                open_runtime_service(service_key, DataService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Stream => {
                open_runtime_service(service_key, StreamService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Mail => {
                open_runtime_service(service_key, MailService::open(&context.state_dir)).await
            }
            unexpected => Err(unexpected_runtime_group_service(
                RuntimeLogicalServiceGroup::DataAndMessaging,
                unexpected,
            )),
        }?;
        services.push(service);
    }
    Ok(services)
}

async fn build_governance_and_operations_services(
    service_keys: &[RuntimeServiceKey],
    context: &RuntimeServiceFactoryContext,
) -> Result<Vec<ActivatedRuntimeService>> {
    let mut services = Vec::with_capacity(service_keys.len());
    for service_key in service_keys.iter().copied() {
        let service = match service_key {
            RuntimeServiceKey::Governance => {
                open_runtime_service(service_key, GovernanceService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Billing => {
                open_runtime_service(service_key, BillingService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Notify => {
                open_runtime_service(service_key, NotifyService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Observe => {
                open_runtime_service(service_key, ObserveService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::Abuse => {
                open_runtime_service(service_key, AbuseService::open(&context.state_dir)).await
            }
            unexpected => Err(unexpected_runtime_group_service(
                RuntimeLogicalServiceGroup::GovernanceAndOperations,
                unexpected,
            )),
        }?;
        services.push(service);
    }
    Ok(services)
}

async fn build_uvm_services(
    service_keys: &[RuntimeServiceKey],
    context: &RuntimeServiceFactoryContext,
) -> Result<Vec<ActivatedRuntimeService>> {
    let mut services = Vec::with_capacity(service_keys.len());
    for service_key in service_keys.iter().copied() {
        let service = match service_key {
            RuntimeServiceKey::UvmControl => {
                open_runtime_service(service_key, UvmControlService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::UvmImage => {
                open_runtime_service(service_key, UvmImageService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::UvmNode => {
                open_runtime_service(service_key, UvmNodeService::open(&context.state_dir)).await
            }
            RuntimeServiceKey::UvmObserve => {
                open_runtime_service(service_key, UvmObserveService::open(&context.state_dir)).await
            }
            unexpected => Err(unexpected_runtime_group_service(
                RuntimeLogicalServiceGroup::Uvm,
                unexpected,
            )),
        }?;
        services.push(service);
    }
    Ok(services)
}

#[cfg(test)]
mod tests {
    use super::deployment_descriptors;

    const SNAPSHOT_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/snapshots/activation_deployment_descriptors.json"
    );
    const UPDATE_SNAPSHOT_ENV: &str = "UPDATE_ACTIVATION_DEPLOYMENT_DESCRIPTORS";

    #[test]
    fn activation_deployment_descriptors_match_snapshot() {
        let rendered = format!(
            "{}\n",
            serde_json::to_string_pretty(&deployment_descriptors::catalog())
                .unwrap_or_else(|error| panic!("{error}"))
        );

        if std::env::var_os(UPDATE_SNAPSHOT_ENV).is_some() {
            std::fs::write(SNAPSHOT_PATH, &rendered)
                .unwrap_or_else(|error| panic!("failed to update activation snapshot: {error}"));
        }

        let snapshot = std::fs::read_to_string(SNAPSHOT_PATH)
            .unwrap_or_else(|error| panic!("failed to read activation snapshot: {error}"));
        assert_eq!(rendered, snapshot);
    }
}
