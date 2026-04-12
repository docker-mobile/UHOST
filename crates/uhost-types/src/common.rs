//! Common resource metadata and operational enums.
//!
//! These types intentionally avoid service-specific fields so they can travel
//! across contracts, audit records, and generic storage layers without leaking a
//! bounded context's internal representation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::id::{ChangeRequestId, EdgePublicationTargetId, PolicyId, PrivateNetworkId, ZoneId};

/// Validation failures for shared resource metadata and actor envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// A required string field was empty or whitespace-only.
    EmptyField {
        /// Type that owns the field.
        type_name: &'static str,
        /// Field name.
        field: &'static str,
    },
    /// A timestamp invariant was violated.
    InvalidTimestampOrder {
        /// Type that owns the timestamps.
        type_name: &'static str,
        /// Human-readable invariant.
        message: &'static str,
    },
    /// A field held a value outside its allowed range.
    InvalidValue {
        /// Type that owns the field.
        type_name: &'static str,
        /// Field name.
        field: &'static str,
        /// Human-readable invariant.
        message: &'static str,
    },
    /// A metadata key was not normalized to lowercase.
    NonNormalizedKey {
        /// Field containing the key/value pairs.
        field: &'static str,
        /// Invalid key value.
        key: String,
    },
    /// A deletion marker was inconsistent with lifecycle state.
    InvalidDeletionState {
        /// Human-readable invariant.
        message: &'static str,
    },
}

/// Shared lifecycle states for resources exposed through the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceLifecycleState {
    /// The resource was accepted but not yet admitted or provisioned.
    Pending,
    /// The resource is healthy enough to serve traffic or accept mutations.
    Ready,
    /// The resource is accepting no new work and is draining.
    Draining,
    /// The resource is paused or suspended by policy or operators.
    Suspended,
    /// The resource has encountered a failure that requires attention.
    Failed,
    /// The resource has been soft-deleted and may be restored before purge.
    Deleted,
}

/// Owner scope of a resource for quota, audit, and chargeback purposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipScope {
    /// The resource is globally owned by platform operators.
    Platform,
    /// The resource belongs to a tenant.
    Tenant,
    /// The resource belongs to a project.
    Project,
    /// The resource belongs to a single user.
    User,
}

/// Scheduling priority classes used by workloads and maintenance operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorityClass {
    /// Lowest priority, safe to preempt first.
    BestEffort,
    /// Default interactive workloads.
    Standard,
    /// High priority workloads and maintenance windows.
    High,
    /// Platform-critical workloads that should only be evicted last.
    Critical,
}

/// Portable network protocol contract for ingress and private networking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// Hypertext Transfer Protocol.
    Http,
    /// Encrypted HTTP.
    Https,
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// WebSocket over HTTP(S).
    WebSocket,
    /// Generic gRPC service over HTTP/2.
    Grpc,
}

/// Explicit exposure intent for one edge publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EdgeExposureIntent {
    /// Publicly reachable north-south publication.
    #[default]
    Public,
    /// Private publication intended for non-public reachability.
    Private,
}

impl EdgeExposureIntent {
    /// Return the stable string form used across audits and contracts.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}

/// DNS binding reference attached to one edge publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeDnsBinding {
    /// Managed DNS zone authorized for the published hostname.
    pub zone_id: ZoneId,
}

/// Edge inspection/security attachment for one publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeSecurityPolicyAttachment {
    /// Inspection profile identifier from the network-security plane.
    pub inspection_profile_id: PolicyId,
}

/// Explicit private-network attachment for one private publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgePrivateNetworkAttachment {
    /// Private-network identifier from the network-security plane.
    pub private_network_id: PrivateNetworkId,
}

/// Topology-readiness proof for one private network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PrivateNetworkTopologyReadiness {
    /// Whether the topology has enough routed structure to support private exposure.
    pub ready: bool,
    /// Total subnets declared for the private network.
    pub subnet_count: usize,
    /// Subnets explicitly associated with a route table.
    pub subnets_with_route_table_count: usize,
    /// Total route tables declared for the private network.
    pub route_table_count: usize,
    /// Total private routes declared for the private network.
    pub private_route_count: usize,
    /// Private routes that currently resolve to a usable path.
    pub ready_private_route_count: usize,
    /// Service-connect attachments anchored to usable private routes.
    pub service_connect_attachment_count: usize,
    /// NAT gateways attached to route tables in this private network.
    pub nat_gateway_count: usize,
    /// Transit attachments attached to route tables in this private network.
    pub transit_attachment_count: usize,
    /// VPN connections attached to route tables in this private network.
    pub vpn_connection_count: usize,
    /// Peering connections attached to route tables in this private network.
    pub peering_connection_count: usize,
    /// Human-readable reasons explaining why the topology is not yet ready.
    #[serde(default)]
    pub missing_requirements: Vec<String>,
}

/// One explicit publication target independent from the route backend pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgePublicationTarget {
    /// Stable target identifier used for later publication mutations.
    pub id: EdgePublicationTargetId,
    /// Cell responsible for serving this publication target.
    pub cell: String,
    /// Region that owns the serving cell.
    pub region: String,
    /// Optional failover group used to coordinate multi-target cutovers.
    #[serde(default)]
    pub failover_group: Option<String>,
    /// Explicit drain intent for this publication target.
    #[serde(default)]
    pub drain: bool,
    /// Named owner for the TLS material or certificate lifecycle.
    pub tls_owner: String,
}

/// Reusable edge publication envelope for services that expose traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgePublication {
    /// Explicit exposure intent.
    #[serde(default)]
    pub exposure: EdgeExposureIntent,
    /// Optional managed DNS binding for the publication hostname.
    #[serde(default)]
    pub dns_binding: Option<EdgeDnsBinding>,
    /// Optional edge inspection/security attachment.
    #[serde(default)]
    pub security_policy: Option<EdgeSecurityPolicyAttachment>,
    /// Optional private-network attachment for private publications.
    #[serde(default)]
    pub private_network: Option<EdgePrivateNetworkAttachment>,
    /// Explicit edge publication targets independent from backend pools.
    #[serde(default)]
    pub targets: Vec<EdgePublicationTarget>,
}

impl Default for EdgePublication {
    fn default() -> Self {
        Self {
            exposure: EdgeExposureIntent::Public,
            dns_binding: None,
            security_policy: None,
            private_network: None,
            targets: Vec::new(),
        }
    }
}

/// Runtime operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceMode {
    /// All services are hosted in a single process for low-ops installs.
    AllInOne,
    /// One process per service on a single machine.
    SingleNode,
    /// Multiple nodes and optionally multiple regions.
    Distributed,
}

/// Categories of authenticated principals recognized by the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// Platform-internal automation without an external user session.
    System,
    /// Human or automation operator acting with platform-wide authority.
    Operator,
    /// End-user identity such as a console account or API consumer.
    User,
    /// Service or workload credential used for platform automation.
    Workload,
}

impl PrincipalKind {
    /// Return the stable string form used across contracts and audits.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Operator => "operator",
            Self::User => "user",
            Self::Workload => "workload",
        }
    }
}

/// Explicit principal attribution propagated through requests and durable identity records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalIdentity {
    /// Principal category.
    pub kind: PrincipalKind,
    /// Stable principal subject string, such as `bootstrap_admin`, `user:alice`, or `svc:builder`.
    pub subject: String,
    /// Optional credential or durable record identifier bound to this principal.
    pub credential_id: Option<String>,
}

impl PrincipalIdentity {
    /// Build a new principal identity envelope.
    pub fn new(kind: PrincipalKind, subject: impl Into<String>) -> Self {
        Self {
            kind,
            subject: subject.into(),
            credential_id: None,
        }
    }

    /// Attach a credential or durable record identifier.
    pub fn with_credential_id(mut self, credential_id: impl Into<String>) -> Self {
        self.credential_id = Some(credential_id.into());
        self
    }

    /// Validate the principal envelope invariants.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.subject.trim().is_empty() {
            return Err(ValidationError::EmptyField {
                type_name: "PrincipalIdentity",
                field: "subject",
            });
        }

        if let Some(credential_id) = &self.credential_id
            && credential_id.trim().is_empty()
        {
            return Err(ValidationError::EmptyField {
                type_name: "PrincipalIdentity",
                field: "credential_id",
            });
        }

        Ok(())
    }
}

/// Shared request provenance captured for governance approvals and change-bound mutations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceRequestProvenance {
    /// Authenticated actor bound to the request when known.
    pub authenticated_actor: String,
    /// Typed principal envelope resolved by the runtime when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalIdentity>,
    /// Correlation identifier propagated across the request chain.
    pub correlation_id: String,
    /// Per-hop request identifier.
    pub request_id: String,
}

/// Durable governance authorization attached to one mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceChangeAuthorization {
    /// Governance change request that authorized this mutation.
    pub change_request_id: ChangeRequestId,
    /// Stable mutation digest bound to the authorized payload.
    pub mutation_digest: String,
    /// Timestamp when the authorization envelope was bound to the mutation.
    pub authorized_at: OffsetDateTime,
    /// Request provenance that carried the authorization.
    pub provenance: GovernanceRequestProvenance,
}

/// Rolling quota window definition used by billing and abuse systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaWindow {
    /// Per-minute quota.
    Minute,
    /// Per-hour quota.
    Hour,
    /// Per-day quota.
    Day,
    /// Per-month quota.
    Month,
}

/// Generic resource metadata persisted alongside all mutable domain records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceMetadata {
    /// Creation timestamp. This field is immutable after the first write.
    pub created_at: OffsetDateTime,
    /// Last mutation timestamp. Updated on every successful write.
    pub updated_at: OffsetDateTime,
    /// Shared lifecycle state used by generic control-plane tooling.
    pub lifecycle: ResourceLifecycleState,
    /// Owning scope for chargeback and policy.
    pub ownership_scope: OwnershipScope,
    /// Optional owner identifier string when known.
    pub owner_id: Option<String>,
    /// Tenant-visible labels. Keys are normalized to lowercase.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// System-generated annotations for operators.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    /// Soft-delete marker. `None` means the record is still active.
    pub deleted_at: Option<OffsetDateTime>,
    /// Optimistic concurrency token stored as a string for transport stability.
    pub etag: String,
}

impl ResourceMetadata {
    /// Create metadata for a freshly admitted resource.
    pub fn new(ownership_scope: OwnershipScope, owner_id: Option<String>, etag: String) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            created_at: now,
            updated_at: now,
            lifecycle: ResourceLifecycleState::Pending,
            ownership_scope,
            owner_id,
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            deleted_at: None,
            etag,
        }
    }

    /// Mark the resource as updated and refresh the ETag.
    pub fn touch(&mut self, etag: String) {
        self.updated_at = OffsetDateTime::now_utc();
        self.etag = etag;
    }

    /// Validate the metadata invariants.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.etag.trim().is_empty() {
            return Err(ValidationError::EmptyField {
                type_name: "ResourceMetadata",
                field: "etag",
            });
        }

        if self.updated_at < self.created_at {
            return Err(ValidationError::InvalidTimestampOrder {
                type_name: "ResourceMetadata",
                message: "updated_at must be greater than or equal to created_at",
            });
        }

        if let Some(deleted_at) = self.deleted_at {
            if deleted_at < self.created_at {
                return Err(ValidationError::InvalidTimestampOrder {
                    type_name: "ResourceMetadata",
                    message: "deleted_at must be greater than or equal to created_at",
                });
            }

            if self.lifecycle != ResourceLifecycleState::Deleted {
                return Err(ValidationError::InvalidDeletionState {
                    message: "deleted_at requires lifecycle to be deleted",
                });
            }
        } else if self.lifecycle == ResourceLifecycleState::Deleted {
            return Err(ValidationError::InvalidDeletionState {
                message: "deleted lifecycle requires deleted_at to be present",
            });
        }

        if let Some(owner_id) = &self.owner_id
            && owner_id.trim().is_empty()
        {
            return Err(ValidationError::EmptyField {
                type_name: "ResourceMetadata",
                field: "owner_id",
            });
        }

        for (field, entries) in [("labels", &self.labels), ("annotations", &self.annotations)] {
            for key in entries.keys() {
                if key.trim().is_empty() {
                    return Err(ValidationError::EmptyField {
                        type_name: "ResourceMetadata",
                        field,
                    });
                }

                if key != &key.to_lowercase() {
                    return Err(ValidationError::NonNormalizedKey {
                        field,
                        key: key.clone(),
                    });
                }
            }
        }

        Ok(())
    }
}

impl GovernanceChangeAuthorization {
    /// Project the authorization envelope into operator-visible metadata annotations.
    pub fn annotate_metadata(
        &self,
        metadata: &mut ResourceMetadata,
        mutation_digest_annotation_key: &str,
    ) {
        metadata.annotations.insert(
            String::from("governance.change_request_id"),
            self.change_request_id.to_string(),
        );
        metadata.annotations.insert(
            String::from("governance.authenticated_actor"),
            self.provenance.authenticated_actor.clone(),
        );
        metadata.annotations.insert(
            String::from("governance.correlation_id"),
            self.provenance.correlation_id.clone(),
        );
        metadata.annotations.insert(
            String::from("governance.request_id"),
            self.provenance.request_id.clone(),
        );
        metadata.annotations.insert(
            mutation_digest_annotation_key.to_owned(),
            self.mutation_digest.clone(),
        );
        if let Some(principal) = self.provenance.principal.as_ref() {
            metadata.annotations.insert(
                String::from("governance.principal_kind"),
                principal.kind.as_str().to_owned(),
            );
            metadata.annotations.insert(
                String::from("governance.principal_subject"),
                principal.subject.clone(),
            );
            if let Some(credential_id) = principal.credential_id.as_ref() {
                metadata.annotations.insert(
                    String::from("governance.principal_credential_id"),
                    credential_id.clone(),
                );
            }
        }
    }
}

/// Actor metadata included in audit events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditActor {
    /// Actor subject identifier, such as a user, service account, or node.
    pub subject: String,
    /// Human-readable actor type.
    pub actor_type: String,
    /// Source IP when known. This remains optional for offline tasks.
    pub source_ip: Option<String>,
    /// Correlation identifier propagated across services.
    pub correlation_id: String,
}

impl AuditActor {
    /// Validate the actor metadata.
    pub fn validate(&self) -> Result<(), ValidationError> {
        for (field, value) in [
            ("subject", &self.subject),
            ("actor_type", &self.actor_type),
            ("correlation_id", &self.correlation_id),
        ] {
            if value.trim().is_empty() {
                return Err(ValidationError::EmptyField {
                    type_name: "AuditActor",
                    field,
                });
            }
        }

        if matches!(self.source_ip.as_deref(), Some(value) if value.trim().is_empty()) {
            return Err(ValidationError::EmptyField {
                type_name: "AuditActor",
                field: "source_ip",
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuditActor, PrincipalIdentity, PrincipalKind, ResourceLifecycleState, ResourceMetadata,
    };
    use time::OffsetDateTime;

    #[test]
    fn metadata_validation_rejects_deleted_without_marker() {
        let metadata = ResourceMetadata {
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            lifecycle: ResourceLifecycleState::Deleted,
            ownership_scope: super::OwnershipScope::Tenant,
            owner_id: None,
            labels: Default::default(),
            annotations: Default::default(),
            deleted_at: None,
            etag: "etag".to_owned(),
        };

        assert!(metadata.validate().is_err());
    }

    #[test]
    fn actor_validation_rejects_blank_fields() {
        let actor = AuditActor {
            subject: " ".to_owned(),
            actor_type: "user".to_owned(),
            source_ip: None,
            correlation_id: "corr".to_owned(),
        };

        assert!(actor.validate().is_err());
    }

    #[test]
    fn principal_validation_rejects_blank_subject() {
        let principal = PrincipalIdentity::new(PrincipalKind::Workload, "   ");

        assert!(principal.validate().is_err());
    }
}
