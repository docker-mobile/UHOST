use std::collections::BTreeMap;
use std::sync::{Arc, RwLock as StdRwLock};

use serde::Serialize;
use time::OffsetDateTime;

use uhost_types::ServiceMode;

/// Explicit runtime process roles used to phase the control plane toward split-process topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProcessRole {
    /// Current single-process composition that owns every logical service group.
    #[default]
    AllInOne,
    /// Future north-south edge or ingress-specialized process.
    Edge,
    /// Future controller or API orchestration process.
    Controller,
    /// Future async worker or mutation-heavy background process.
    Worker,
    /// Future node-adjacent or data-plane-near process.
    NodeAdjacent,
}

impl RuntimeProcessRole {
    /// Return the stable string form used by logs, JSON reporting, and contracts.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllInOne => "all_in_one",
            Self::Edge => "edge",
            Self::Controller => "controller",
            Self::Worker => "worker",
            Self::NodeAdjacent => "node_adjacent",
        }
    }
}

/// Logical runtime service-group buckets owned by one process role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLogicalServiceGroup {
    /// Console, ingress, and DNS entry surfaces.
    Edge,
    /// Identity, tenancy, policy, and secret-bearing control surfaces.
    IdentityAndPolicy,
    /// Core control, placement, lifecycle, and node orchestration surfaces.
    Control,
    /// Network, storage, data, and message-adjacent services.
    DataAndMessaging,
    /// Governance, billing, notification, abuse, and observation overlays.
    GovernanceAndOperations,
    /// UVM control, image, node, and observe services.
    Uvm,
}

impl RuntimeLogicalServiceGroup {
    /// Return the stable string form used by logs, JSON reporting, and contracts.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Edge => "edge",
            Self::IdentityAndPolicy => "identity_and_policy",
            Self::Control => "control",
            Self::DataAndMessaging => "data_and_messaging",
            Self::GovernanceAndOperations => "governance_and_operations",
            Self::Uvm => "uvm",
        }
    }

    /// Return every supported logical service-group identifier in deterministic order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::Edge,
            Self::IdentityAndPolicy,
            Self::Control,
            Self::DataAndMessaging,
            Self::GovernanceAndOperations,
            Self::Uvm,
        ]
    }

    /// Parse one stable string form into the logical service-group identifier.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "edge" => Some(Self::Edge),
            "identity_and_policy" => Some(Self::IdentityAndPolicy),
            "control" => Some(Self::Control),
            "data_and_messaging" => Some(Self::DataAndMessaging),
            "governance_and_operations" => Some(Self::GovernanceAndOperations),
            "uvm" => Some(Self::Uvm),
            _ => None,
        }
    }
}

/// Runtime readiness state published for the current process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeReadinessState {
    /// Process has registered but is not yet ready.
    #[default]
    Starting,
    /// Process is ready.
    Ready,
}

/// Runtime drain intent published for the current process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDrainIntent {
    /// Process is serving normally.
    #[default]
    Serving,
    /// Process is draining and preparing to stop serving.
    Draining,
}

/// Freshness state of the current process lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLeaseFreshness {
    /// Lease is current.
    Fresh,
    /// Lease is nearing expiration.
    Stale,
    /// Lease has expired.
    Expired,
}

/// Source used to derive one participant's effective lease freshness and associated availability state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeParticipantLeaseSource {
    /// State came from a currently linked lease registration.
    LinkedRegistration,
    /// State was derived from previously published participant state because no linked lease registration was available.
    #[default]
    PublishedStateFallback,
}

/// Explicit reason why lease safety degraded the effective participant state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeParticipantDegradedReason {
    /// Effective drain was forced because the lease is nearing expiration.
    LeaseStale,
    /// Effective drain was forced because the lease has expired.
    LeaseExpired,
}

/// Explicit graceful-drain phase carried independently from lease freshness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeParticipantDrainPhase {
    /// Participant is serving normally with no graceful drain in progress.
    #[default]
    Serving,
    /// Participant requested drain and now waits for a replacement to take over.
    TakeoverPending,
    /// Participant requested drain and a replacement acknowledged takeover.
    TakeoverAcknowledged,
}

/// Current process lease state published through runtime topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeLeaseState {
    /// Most recent successful renewal time.
    pub renewed_at: OffsetDateTime,
    /// Lease expiration time.
    pub expires_at: OffsetDateTime,
    /// Requested lease duration in whole seconds.
    pub duration_seconds: u32,
    /// Computed freshness state.
    pub freshness: RuntimeLeaseFreshness,
}

impl RuntimeLeaseState {
    /// Build one lease state record.
    pub fn new(
        renewed_at: OffsetDateTime,
        expires_at: OffsetDateTime,
        duration_seconds: u32,
        freshness: RuntimeLeaseFreshness,
    ) -> Self {
        Self {
            renewed_at,
            expires_at,
            duration_seconds: duration_seconds.max(1),
            freshness,
        }
    }
}

/// Region membership published through runtime topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeRegionMembership {
    /// Stable region identifier.
    pub region_id: String,
    /// Human-meaningful region name.
    pub region_name: String,
}

impl Default for RuntimeRegionMembership {
    fn default() -> Self {
        Self::local()
    }
}

impl RuntimeRegionMembership {
    /// Build one runtime region membership record.
    pub fn new(region_id: impl Into<String>, region_name: impl Into<String>) -> Self {
        Self {
            region_id: trimmed_or_fallback(region_id, "local"),
            region_name: trimmed_or_fallback(region_name, "local"),
        }
    }

    /// Build the safe local-development default region membership.
    pub fn local() -> Self {
        Self::new("local", "local")
    }
}

/// Cell membership published through runtime topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeCellMembership {
    /// Stable cell identifier.
    pub cell_id: String,
    /// Human-meaningful cell name.
    pub cell_name: String,
}

impl Default for RuntimeCellMembership {
    fn default() -> Self {
        Self::local()
    }
}

impl RuntimeCellMembership {
    /// Build one runtime cell membership record.
    pub fn new(cell_id: impl Into<String>, cell_name: impl Into<String>) -> Self {
        Self {
            cell_id: trimmed_or_fallback(cell_id, "local:local-cell"),
            cell_name: trimmed_or_fallback(cell_name, "local-cell"),
        }
    }

    /// Build the safe local-development default cell membership.
    pub fn local() -> Self {
        Self::new("local:local-cell", "local-cell")
    }
}

/// Participant registration published through runtime topology for the current cell slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeParticipantState {
    /// Current readiness state for the participant.
    pub readiness: RuntimeReadinessState,
    /// Current drain intent for the participant.
    pub drain_intent: RuntimeDrainIntent,
    /// Originally published drain intent before lease-safety degradation forced draining.
    pub published_drain_intent: RuntimeDrainIntent,
    /// Explicit graceful-drain phase tracked independently from lease freshness degradation.
    pub drain_phase: RuntimeParticipantDrainPhase,
    /// Registration currently acknowledged as the takeover target for this drain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub takeover_registration_id: Option<String>,
    /// Timestamp when the replacement registration acknowledged takeover.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub takeover_acknowledged_at: Option<OffsetDateTime>,
    /// Explicit reason when lease safety degraded the effective state beyond the published drain intent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded_reason: Option<RuntimeParticipantDegradedReason>,
    /// Source used to derive effective lease freshness and associated availability state.
    pub lease_source: RuntimeParticipantLeaseSource,
    /// Current lease snapshot for the participant.
    pub lease: RuntimeLeaseState,
}

impl RuntimeParticipantState {
    /// Build one runtime participant state record.
    pub fn new(
        readiness: RuntimeReadinessState,
        drain_intent: RuntimeDrainIntent,
        lease: RuntimeLeaseState,
    ) -> Self {
        let mut state = Self {
            readiness,
            drain_intent,
            published_drain_intent: drain_intent,
            drain_phase: RuntimeParticipantDrainPhase::Serving,
            takeover_registration_id: None,
            takeover_acknowledged_at: None,
            degraded_reason: None,
            lease_source: RuntimeParticipantLeaseSource::PublishedStateFallback,
            lease,
        };
        state.recompute_derived_state();
        state
    }

    fn recompute_degraded_reason(&mut self) {
        self.degraded_reason = degraded_reason_for_effective_state(
            self.drain_intent,
            self.published_drain_intent,
            self.lease.freshness,
        );
    }

    fn recompute_drain_phase(&mut self) {
        if self.published_drain_intent != RuntimeDrainIntent::Draining {
            self.drain_phase = RuntimeParticipantDrainPhase::Serving;
            self.takeover_registration_id = None;
            self.takeover_acknowledged_at = None;
            return;
        }

        if self.takeover_registration_id.is_some() && self.takeover_acknowledged_at.is_some() {
            self.drain_phase = RuntimeParticipantDrainPhase::TakeoverAcknowledged;
        } else {
            self.drain_phase = RuntimeParticipantDrainPhase::TakeoverPending;
            self.takeover_registration_id = None;
            self.takeover_acknowledged_at = None;
        }
    }

    fn recompute_derived_state(&mut self) {
        self.recompute_degraded_reason();
        self.recompute_drain_phase();
    }

    /// Override the originally published drain intent when the effective state has been degraded.
    pub fn with_published_drain_intent(
        mut self,
        published_drain_intent: RuntimeDrainIntent,
    ) -> Self {
        self.published_drain_intent = published_drain_intent;
        self.recompute_derived_state();
        self
    }

    /// Override the source used to derive effective participant state.
    pub fn with_lease_source(mut self, lease_source: RuntimeParticipantLeaseSource) -> Self {
        self.lease_source = lease_source;
        self
    }

    /// Attach takeover acknowledgement metadata when a replacement has assumed responsibility.
    pub fn with_takeover_acknowledgement(
        mut self,
        takeover_registration_id: impl Into<String>,
        takeover_acknowledged_at: OffsetDateTime,
    ) -> Self {
        self.takeover_registration_id = trimmed_optional_string(takeover_registration_id);
        self.takeover_acknowledged_at = self
            .takeover_registration_id
            .as_ref()
            .map(|_| takeover_acknowledged_at);
        self.recompute_drain_phase();
        self
    }
}

fn degraded_reason_for_effective_state(
    drain_intent: RuntimeDrainIntent,
    published_drain_intent: RuntimeDrainIntent,
    freshness: RuntimeLeaseFreshness,
) -> Option<RuntimeParticipantDegradedReason> {
    if drain_intent != RuntimeDrainIntent::Draining || published_drain_intent == drain_intent {
        return None;
    }

    match freshness {
        RuntimeLeaseFreshness::Fresh => None,
        RuntimeLeaseFreshness::Stale => Some(RuntimeParticipantDegradedReason::LeaseStale),
        RuntimeLeaseFreshness::Expired => Some(RuntimeParticipantDegradedReason::LeaseExpired),
    }
}

/// Cleanup workflow summary published through runtime topology for one stale participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeParticipantCleanupStage {
    /// Workflow exists but still awaits bounded repeated local review.
    PendingReview,
    /// Local repeated review confirmed the peer remains expired and draining.
    PreflightConfirmed,
    /// Local repeated review confirmed operator-visible tombstone eligibility.
    TombstoneEligible,
}

/// Route-withdrawal preparation artifact published through runtime topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeEvacuationRouteWithdrawalArtifact {
    /// Stable artifact identifier.
    pub artifact_id: String,
    /// Participant registration being withdrawn from service-group routing.
    pub source_participant_registration_id: String,
    /// Logical service groups that should stop resolving to the stale participant.
    pub service_groups: Vec<String>,
    /// Timestamp when the route-withdrawal artifact was first prepared.
    pub prepared_at: OffsetDateTime,
}

impl RuntimeEvacuationRouteWithdrawalArtifact {
    /// Build one runtime route-withdrawal preparation artifact.
    pub fn new(
        artifact_id: impl Into<String>,
        source_participant_registration_id: impl Into<String>,
        service_groups: Vec<String>,
        prepared_at: OffsetDateTime,
    ) -> Self {
        Self {
            artifact_id: trimmed_string(artifact_id),
            source_participant_registration_id: trimmed_string(source_participant_registration_id),
            service_groups: normalized_string_list(service_groups),
            prepared_at,
        }
    }
}

/// Target-readiness preparation artifact published through runtime topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeEvacuationTargetReadinessArtifact {
    /// Stable artifact identifier.
    pub artifact_id: String,
    /// Participant registration being evacuated away from.
    pub source_participant_registration_id: String,
    /// Participant registration selected as the local evacuation target.
    pub target_participant_registration_id: String,
    /// Logical service groups that the selected target must keep ready.
    pub service_groups: Vec<String>,
    /// Timestamp when the target-readiness artifact was first prepared.
    pub prepared_at: OffsetDateTime,
}

impl RuntimeEvacuationTargetReadinessArtifact {
    /// Build one runtime target-readiness preparation artifact.
    pub fn new(
        artifact_id: impl Into<String>,
        source_participant_registration_id: impl Into<String>,
        target_participant_registration_id: impl Into<String>,
        service_groups: Vec<String>,
        prepared_at: OffsetDateTime,
    ) -> Self {
        Self {
            artifact_id: trimmed_string(artifact_id),
            source_participant_registration_id: trimmed_string(source_participant_registration_id),
            target_participant_registration_id: trimmed_string(target_participant_registration_id),
            service_groups: normalized_string_list(service_groups),
            prepared_at,
        }
    }
}

/// Rollback preparation artifact published through runtime topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeEvacuationRollbackArtifact {
    /// Stable artifact identifier.
    pub artifact_id: String,
    /// Participant registration being evacuated away from.
    pub source_participant_registration_id: String,
    /// Participant registration selected as the temporary local target.
    pub target_participant_registration_id: String,
    /// Logical service groups that should be restored if the evacuation is rolled back.
    pub service_groups: Vec<String>,
    /// Timestamp when the rollback artifact was first prepared.
    pub prepared_at: OffsetDateTime,
}

impl RuntimeEvacuationRollbackArtifact {
    /// Build one runtime rollback preparation artifact.
    pub fn new(
        artifact_id: impl Into<String>,
        source_participant_registration_id: impl Into<String>,
        target_participant_registration_id: impl Into<String>,
        service_groups: Vec<String>,
        prepared_at: OffsetDateTime,
    ) -> Self {
        Self {
            artifact_id: trimmed_string(artifact_id),
            source_participant_registration_id: trimmed_string(source_participant_registration_id),
            target_participant_registration_id: trimmed_string(target_participant_registration_id),
            service_groups: normalized_string_list(service_groups),
            prepared_at,
        }
    }
}

/// Cleanup workflow summary published through runtime topology for one stale participant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeParticipantCleanupWorkflow {
    /// Stable workflow identifier.
    pub id: String,
    /// Workflow family associated with the cleanup record.
    pub workflow_kind: String,
    /// Current workflow phase rendered as a stable snake_case string.
    pub phase: String,
    /// Current bounded local cleanup-review stage.
    pub stage: RuntimeParticipantCleanupStage,
    /// Count of local stale observations persisted into the workflow.
    pub review_observations: u32,
    /// Timestamp of the most recent stale observation carried by the workflow.
    pub last_observed_stale_at: OffsetDateTime,
    /// Timestamp when local repeated review first confirmed cleanup preflight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preflight_confirmed_at: Option<OffsetDateTime>,
    /// Prepared route-withdrawal artifact when local evacuation planning has materialized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_withdrawal: Option<RuntimeEvacuationRouteWithdrawalArtifact>,
    /// Prepared target-readiness artifact when local evacuation planning has materialized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_readiness: Option<RuntimeEvacuationTargetReadinessArtifact>,
    /// Prepared rollback artifact when local evacuation planning has materialized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback: Option<RuntimeEvacuationRollbackArtifact>,
    /// Timestamp when local repeated review first marked tombstone eligibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tombstone_eligible_at: Option<OffsetDateTime>,
    /// Workflow creation timestamp.
    pub created_at: OffsetDateTime,
    /// Workflow last-update timestamp.
    pub updated_at: OffsetDateTime,
}

impl RuntimeParticipantCleanupWorkflow {
    /// Build one runtime cleanup workflow summary.
    pub fn new(
        id: impl Into<String>,
        workflow_kind: impl Into<String>,
        phase: impl Into<String>,
        stage: RuntimeParticipantCleanupStage,
        review_observations: u32,
        last_observed_stale_at: OffsetDateTime,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Self {
        Self {
            id: trimmed_string(id),
            workflow_kind: trimmed_string(workflow_kind),
            phase: trimmed_string(phase),
            stage,
            review_observations: review_observations.max(1),
            last_observed_stale_at,
            preflight_confirmed_at: None,
            route_withdrawal: None,
            target_readiness: None,
            rollback: None,
            tombstone_eligible_at: None,
            created_at,
            updated_at,
        }
    }

    /// Attach the first local preflight-confirmed timestamp when one exists.
    pub fn with_preflight_confirmed_at(mut self, preflight_confirmed_at: OffsetDateTime) -> Self {
        self.preflight_confirmed_at = Some(preflight_confirmed_at);
        self
    }

    /// Attach one route-withdrawal preparation artifact when one exists.
    pub fn with_route_withdrawal(
        mut self,
        route_withdrawal: RuntimeEvacuationRouteWithdrawalArtifact,
    ) -> Self {
        self.route_withdrawal = Some(route_withdrawal);
        self
    }

    /// Attach one target-readiness preparation artifact when one exists.
    pub fn with_target_readiness(
        mut self,
        target_readiness: RuntimeEvacuationTargetReadinessArtifact,
    ) -> Self {
        self.target_readiness = Some(target_readiness);
        self
    }

    /// Attach one rollback preparation artifact when one exists.
    pub fn with_rollback(mut self, rollback: RuntimeEvacuationRollbackArtifact) -> Self {
        self.rollback = Some(rollback);
        self
    }

    /// Attach the first local tombstone-eligibility timestamp when one exists.
    pub fn with_tombstone_eligible_at(mut self, tombstone_eligible_at: OffsetDateTime) -> Self {
        self.tombstone_eligible_at = Some(tombstone_eligible_at);
        self
    }
}

/// Reconciliation metadata published through runtime topology for one participant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeParticipantReconciliation {
    /// Timestamp of the most recent participant reconciliation pass.
    pub last_reconciled_at: OffsetDateTime,
    /// Timestamp when the participant first entered a stale or expired state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_since: Option<OffsetDateTime>,
    /// Optional cleanup workflow summary when one exists for this participant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_workflow: Option<RuntimeParticipantCleanupWorkflow>,
}

impl RuntimeParticipantReconciliation {
    /// Build one runtime participant reconciliation record.
    pub fn new(last_reconciled_at: OffsetDateTime) -> Self {
        Self {
            last_reconciled_at,
            stale_since: None,
            cleanup_workflow: None,
        }
    }

    /// Attach the first observed stale timestamp when one exists.
    pub fn with_stale_since(mut self, stale_since: OffsetDateTime) -> Self {
        self.stale_since = Some(stale_since);
        self
    }

    /// Attach cleanup workflow metadata when one exists.
    pub fn with_cleanup_workflow(
        mut self,
        cleanup_workflow: RuntimeParticipantCleanupWorkflow,
    ) -> Self {
        self.cleanup_workflow = Some(cleanup_workflow);
        self
    }
}

/// Durable tombstone history published through runtime topology after a participant leaves live state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeParticipantTombstoneHistoryEntry {
    /// Stable event identifier linking history, audit, and replayable relay evidence.
    pub event_id: String,
    /// Stable cell identifier where the tombstone occurred.
    pub cell_id: String,
    /// Human-meaningful cell name for operator reporting.
    pub cell_name: String,
    /// Stable region identifier owning the cell at mutation time.
    pub region_id: String,
    /// Human-meaningful region name for operator reporting.
    pub region_name: String,
    /// Stable participant registration identifier removed from the live cell directory.
    pub participant_registration_id: String,
    /// Broad participant family associated with the removed registration.
    pub participant_kind: String,
    /// Stable participant subject identifier associated with the removed registration.
    pub participant_subject_id: String,
    /// Role or ownership label carried by the removed participant.
    pub participant_role: String,
    /// Optional node name associated with the removed participant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// Logical service groups owned by the removed participant.
    pub service_groups: Vec<String>,
    /// Linked cleanup workflow identifier that authorized the destructive mutation.
    pub cleanup_workflow_id: String,
    /// Count of stale observations that led to the operator-visible tombstone decision.
    pub review_observations: u32,
    /// Timestamp when the participant first entered the stale or expired state.
    pub stale_since: OffsetDateTime,
    /// Timestamp when local repeated review first confirmed cleanup preflight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preflight_confirmed_at: Option<OffsetDateTime>,
    /// Timestamp when local repeated review first marked the participant tombstone-eligible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tombstone_eligible_at: Option<OffsetDateTime>,
    /// Timestamp when the operator-approved tombstone completed.
    pub tombstoned_at: OffsetDateTime,
    /// Operator or controller subject recorded for the mutation.
    pub actor_subject: String,
    /// Actor kind recorded for the mutation.
    pub actor_type: String,
    /// Correlation identifier linking history, audit, and relay evidence.
    pub correlation_id: String,
    /// Optional linked lease registration removed alongside the participant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_registration_id: Option<String>,
    /// Originally published drain intent before lease-safety degradation forced draining at tombstone time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_drain_intent: Option<RuntimeDrainIntent>,
    /// Explicit reason when lease safety degraded the effective state beyond the published drain intent at tombstone time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded_reason: Option<RuntimeParticipantDegradedReason>,
    /// Source used to derive effective lease freshness and associated availability state at tombstone time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_source: Option<RuntimeParticipantLeaseSource>,
    /// Whether the participant was removed from the live cell directory.
    pub removed_from_cell_directory: bool,
    /// Whether the linked lease registration was soft-deleted.
    pub lease_registration_soft_deleted: bool,
    /// Whether the linked cleanup workflow was soft-deleted after completion.
    pub cleanup_workflow_soft_deleted: bool,
}

/// Participant registration published through runtime topology for the current cell slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeParticipantRegistration {
    /// Stable participant registration identifier.
    pub registration_id: String,
    /// Broad participant family (`runtime_process`, `service_group`, etc.).
    pub participant_kind: String,
    /// Stable subject identifier associated with the participant.
    pub subject_id: String,
    /// Role or ownership label carried by the participant.
    pub role: String,
    /// Optional node name associated with the participant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// Logical service groups owned by the participant.
    pub service_groups: Vec<String>,
    /// Timestamp when the participant registration was published.
    pub registered_at: OffsetDateTime,
    /// Optional linked lease-registration identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_registration_id: Option<String>,
    /// Optional reconciled readiness, drain, and lease snapshot for the participant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<RuntimeParticipantState>,
    /// Optional stale or reconciliation metadata and cleanup workflow status for the participant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconciliation: Option<RuntimeParticipantReconciliation>,
}

impl RuntimeParticipantRegistration {
    /// Build one runtime participant registration record.
    pub fn new(
        registration_id: impl Into<String>,
        participant_kind: impl Into<String>,
        subject_id: impl Into<String>,
        role: impl Into<String>,
        registered_at: OffsetDateTime,
    ) -> Self {
        Self {
            registration_id: trimmed_string(registration_id),
            participant_kind: trimmed_string(participant_kind),
            subject_id: trimmed_string(subject_id),
            role: trimmed_string(role),
            node_name: None,
            service_groups: Vec::new(),
            registered_at,
            lease_registration_id: None,
            state: None,
            reconciliation: None,
        }
    }

    /// Attach an optional node name when constructing a participant record.
    pub fn with_node_name(mut self, node_name: impl Into<String>) -> Self {
        self.node_name = trimmed_optional_string(node_name);
        self
    }

    /// Attach owned logical service groups when constructing a participant record.
    pub fn with_service_groups<I, S>(mut self, service_groups: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.service_groups = normalized_string_list(service_groups);
        self
    }

    /// Attach a linked lease-registration identifier when one exists.
    pub fn with_lease_registration_id(mut self, lease_registration_id: impl Into<String>) -> Self {
        self.lease_registration_id = trimmed_optional_string(lease_registration_id);
        self
    }

    /// Attach reconciled readiness, drain, and lease state when one exists.
    pub fn with_state(mut self, state: RuntimeParticipantState) -> Self {
        self.state = Some(state);
        self
    }

    /// Attach stale or reconciliation metadata when one exists.
    pub fn with_reconciliation(mut self, reconciliation: RuntimeParticipantReconciliation) -> Self {
        self.reconciliation = Some(reconciliation);
        self
    }
}

/// Conflict state recorded for one logical service-group resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeServiceGroupConflictState {
    /// No conflicting healthy registrations were observed for the group.
    #[default]
    NoConflict,
    /// Multiple healthy registrations currently claim the same logical group.
    MultipleHealthyRegistrations,
}

/// Reason why one or more registrations were quarantined from healthy group resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeServiceGroupQuarantineReason {
    /// Runtime registration identity or linked lease identity is impossible for the participant.
    InvalidRuntimeRegistrationLink,
    /// The participant would otherwise be healthy, but conflict resolution withheld it.
    HealthyConflict,
}

/// Quarantine summary for one logical service-group directory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeServiceGroupQuarantineSummary {
    /// Stable quarantine reason carried in operator-facing topology.
    pub reason: RuntimeServiceGroupQuarantineReason,
    /// Number of registrations currently quarantined for the reason.
    pub registration_count: usize,
}

impl RuntimeServiceGroupQuarantineSummary {
    /// Build one quarantine summary row.
    pub fn new(reason: RuntimeServiceGroupQuarantineReason, registration_count: usize) -> Self {
        Self {
            reason,
            registration_count,
        }
    }
}

/// One participant registration projected into one logical service-group directory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeServiceGroupRegistrationResolution {
    /// Stable participant registration identifier.
    pub registration_id: String,
    /// Broad participant family (`runtime_process`, `service_group`, etc.).
    pub participant_kind: String,
    /// Stable subject identifier associated with the participant.
    pub subject_id: String,
    /// Role or ownership label carried by the participant.
    pub role: String,
    /// Optional node name associated with the participant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// Optional linked lease-registration identifier associated with the participant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_registration_id: Option<String>,
    /// Timestamp when the participant registration was published.
    pub registered_at: OffsetDateTime,
    /// Optional published readiness state when a reconciled participant state exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readiness: Option<RuntimeReadinessState>,
    /// Optional effective drain intent when a reconciled participant state exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drain_intent: Option<RuntimeDrainIntent>,
    /// Optional graceful-drain phase when a reconciled participant state exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drain_phase: Option<RuntimeParticipantDrainPhase>,
    /// Optional replacement registration that acknowledged takeover for this participant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub takeover_registration_id: Option<String>,
    /// Optional timestamp when the replacement registration acknowledged takeover.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub takeover_acknowledged_at: Option<OffsetDateTime>,
    /// Optional effective lease freshness when a reconciled participant state exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_freshness: Option<RuntimeLeaseFreshness>,
    /// Whether the participant currently resolves as healthy for this logical group.
    pub healthy: bool,
}

impl RuntimeServiceGroupRegistrationResolution {
    /// Build one logical service-group registration resolution record.
    pub fn new(
        registration_id: impl Into<String>,
        participant_kind: impl Into<String>,
        subject_id: impl Into<String>,
        role: impl Into<String>,
        registered_at: OffsetDateTime,
        healthy: bool,
    ) -> Self {
        Self {
            registration_id: trimmed_string(registration_id),
            participant_kind: trimmed_string(participant_kind),
            subject_id: trimmed_string(subject_id),
            role: trimmed_string(role),
            node_name: None,
            lease_registration_id: None,
            registered_at,
            readiness: None,
            drain_intent: None,
            drain_phase: None,
            takeover_registration_id: None,
            takeover_acknowledged_at: None,
            lease_freshness: None,
            healthy,
        }
    }

    /// Attach an optional node name when constructing a record.
    pub fn with_node_name(mut self, node_name: impl Into<String>) -> Self {
        self.node_name = trimmed_optional_string(node_name);
        self
    }

    /// Attach an optional linked lease-registration identifier when one exists.
    pub fn with_lease_registration_id(mut self, lease_registration_id: impl Into<String>) -> Self {
        self.lease_registration_id = trimmed_optional_string(lease_registration_id);
        self
    }

    /// Attach a readiness state when a reconciled participant state exists.
    pub fn with_readiness(mut self, readiness: RuntimeReadinessState) -> Self {
        self.readiness = Some(readiness);
        self
    }

    /// Attach an effective drain intent when a reconciled participant state exists.
    pub fn with_drain_intent(mut self, drain_intent: RuntimeDrainIntent) -> Self {
        self.drain_intent = Some(drain_intent);
        self
    }

    /// Attach a graceful-drain phase when a reconciled participant state exists.
    pub fn with_drain_phase(mut self, drain_phase: RuntimeParticipantDrainPhase) -> Self {
        self.drain_phase = Some(drain_phase);
        self
    }

    /// Attach takeover acknowledgement metadata when a replacement has assumed responsibility.
    pub fn with_takeover_acknowledgement(
        mut self,
        takeover_registration_id: impl Into<String>,
        takeover_acknowledged_at: OffsetDateTime,
    ) -> Self {
        self.takeover_registration_id = trimmed_optional_string(takeover_registration_id);
        self.takeover_acknowledged_at = self
            .takeover_registration_id
            .as_ref()
            .map(|_| takeover_acknowledged_at);
        self
    }

    /// Attach an effective lease freshness when a reconciled participant state exists.
    pub fn with_lease_freshness(mut self, lease_freshness: RuntimeLeaseFreshness) -> Self {
        self.lease_freshness = Some(lease_freshness);
        self
    }
}

/// One logical service-group resolution entry derived from the current cell directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeServiceGroupDirectoryEntry {
    /// Logical service-group identifier.
    pub group: RuntimeLogicalServiceGroup,
    /// Healthy participant registrations currently resolved for this logical group.
    pub resolved_registration_ids: Vec<String>,
    /// Conflict state derived from the current healthy registrations.
    pub conflict_state: RuntimeServiceGroupConflictState,
    /// All participant registrations currently advertising this logical group.
    pub registrations: Vec<RuntimeServiceGroupRegistrationResolution>,
    /// Operator-facing quarantine summaries grouped by reason.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantine_summaries: Vec<RuntimeServiceGroupQuarantineSummary>,
}

impl RuntimeServiceGroupDirectoryEntry {
    /// Build one logical service-group directory entry.
    pub fn new(group: RuntimeLogicalServiceGroup) -> Self {
        Self {
            group,
            resolved_registration_ids: Vec::new(),
            conflict_state: RuntimeServiceGroupConflictState::NoConflict,
            registrations: Vec::new(),
            quarantine_summaries: Vec::new(),
        }
    }

    fn recompute_quarantine_summaries(&mut self) {
        // Quarantine reasons are counted separately: an invalid
        // runtime-registration link is different from a registration that would
        // otherwise be healthy but is quarantined because it conflicts with
        // another claimant for the same logical service group.
        let invalid_runtime_registration_link_count = self
            .registrations
            .iter()
            .filter(|registration| {
                !registration.healthy
                    && runtime_service_group_registration_has_invalid_runtime_link(registration)
            })
            .count();
        let healthy_conflict_count = self
            .registrations
            .iter()
            .filter(|registration| {
                !registration.healthy
                    && !runtime_service_group_registration_has_invalid_runtime_link(registration)
                    && runtime_service_group_registration_base_health(registration)
            })
            .count();
        let mut quarantine_summaries = Vec::new();
        if invalid_runtime_registration_link_count > 0 {
            quarantine_summaries.push(RuntimeServiceGroupQuarantineSummary::new(
                RuntimeServiceGroupQuarantineReason::InvalidRuntimeRegistrationLink,
                invalid_runtime_registration_link_count,
            ));
        }
        if healthy_conflict_count > 0 {
            quarantine_summaries.push(RuntimeServiceGroupQuarantineSummary::new(
                RuntimeServiceGroupQuarantineReason::HealthyConflict,
                healthy_conflict_count,
            ));
        }
        self.quarantine_summaries = quarantine_summaries;
    }

    /// Attach resolved healthy registration identifiers when constructing a record.
    pub fn with_resolved_registration_ids<I, S>(mut self, registration_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.resolved_registration_ids = normalized_string_list(registration_ids);
        self
    }

    /// Attach the current group conflict state.
    pub fn with_conflict_state(mut self, conflict_state: RuntimeServiceGroupConflictState) -> Self {
        self.conflict_state = conflict_state;
        self.recompute_quarantine_summaries();
        self
    }

    /// Attach the current participant registrations advertising this logical group.
    pub fn with_registrations<I>(mut self, registrations: I) -> Self
    where
        I: IntoIterator<Item = RuntimeServiceGroupRegistrationResolution>,
    {
        self.registrations = normalized_service_group_registrations(registrations);
        self.recompute_quarantine_summaries();
        self
    }
}

/// Current process registration state published through runtime topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeProcessState {
    /// Stable durable registration identifier.
    pub registration_id: String,
    /// Current readiness state.
    pub readiness: RuntimeReadinessState,
    /// Current drain intent.
    pub drain_intent: RuntimeDrainIntent,
    /// Registration publication time.
    pub registered_at: OffsetDateTime,
    /// Current lease state.
    pub lease: RuntimeLeaseState,
}

impl RuntimeProcessState {
    /// Build one runtime process state record.
    pub fn new(
        registration_id: impl Into<String>,
        readiness: RuntimeReadinessState,
        drain_intent: RuntimeDrainIntent,
        registered_at: OffsetDateTime,
        lease: RuntimeLeaseState,
    ) -> Self {
        Self {
            registration_id: registration_id.into(),
            readiness,
            drain_intent,
            registered_at,
            lease,
        }
    }
}

/// One logical service-group ownership assignment inside the current runtime topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeServiceGroupOwnership {
    /// Logical service-group identifier.
    pub group: RuntimeLogicalServiceGroup,
    /// Process role that currently owns the group.
    pub owner_role: RuntimeProcessRole,
    /// Stable service names routed through the owned group.
    pub services: Vec<String>,
}

impl RuntimeServiceGroupOwnership {
    /// Build one ownership record with deterministic service ordering.
    pub fn new<I, S>(
        group: RuntimeLogicalServiceGroup,
        owner_role: RuntimeProcessRole,
        services: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut services = services.into_iter().map(Into::into).collect::<Vec<_>>();
        services.sort_unstable();
        services.dedup();
        Self {
            group,
            owner_role,
            services,
        }
    }
}

/// Operator-facing topology report for the current runtime process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeTopology {
    /// Concrete process role currently running in this process.
    pub process_role: RuntimeProcessRole,
    /// Deployment posture carried from configuration.
    pub deployment_mode: ServiceMode,
    /// Optional configured node name for the current process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// Current region membership for this runtime process.
    pub region: RuntimeRegionMembership,
    /// Current cell membership for this runtime process.
    pub cell: RuntimeCellMembership,
    /// Durable registration, readiness, drain, and lease state for the current process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_state: Option<RuntimeProcessState>,
    /// Logical service-group ownership carried by this process.
    pub service_groups: Vec<RuntimeServiceGroupOwnership>,
    /// Durable service-group directory resolved for the current runtime cell slice.
    pub service_group_directory: Vec<RuntimeServiceGroupDirectoryEntry>,
    /// Registered runtime participants currently published for the current cell slice.
    pub participants: Vec<RuntimeParticipantRegistration>,
    /// Recent bounded tombstone history retained after participants leave the live cell slice.
    pub tombstone_history: Vec<RuntimeParticipantTombstoneHistoryEntry>,
}

impl Default for RuntimeTopology {
    fn default() -> Self {
        Self {
            process_role: RuntimeProcessRole::AllInOne,
            deployment_mode: ServiceMode::AllInOne,
            node_name: None,
            region: RuntimeRegionMembership::default(),
            cell: RuntimeCellMembership::default(),
            process_state: None,
            service_groups: Vec::new(),
            service_group_directory: Vec::new(),
            participants: Vec::new(),
            tombstone_history: Vec::new(),
        }
    }
}

impl RuntimeTopology {
    /// Build a topology report for the provided process role.
    pub fn new(process_role: RuntimeProcessRole) -> Self {
        Self {
            process_role,
            ..Self::default()
        }
    }

    /// Attach the configured deployment posture.
    pub fn with_deployment_mode(mut self, deployment_mode: ServiceMode) -> Self {
        self.deployment_mode = deployment_mode;
        self
    }

    /// Attach the configured node name when one is present.
    pub fn with_node_name(mut self, node_name: impl Into<String>) -> Self {
        let node_name = node_name.into();
        let trimmed = node_name.trim();
        self.node_name = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        };
        self
    }

    /// Attach explicit region membership.
    pub fn with_region_membership(mut self, region: RuntimeRegionMembership) -> Self {
        self.region = region;
        self
    }

    /// Attach explicit cell membership.
    pub fn with_cell_membership(mut self, cell: RuntimeCellMembership) -> Self {
        self.cell = cell;
        self
    }

    /// Attach durable process registration and lease state.
    pub fn with_process_state(mut self, process_state: RuntimeProcessState) -> Self {
        self.process_state = Some(process_state);
        self
    }

    /// Add or replace one logical service-group ownership record.
    pub fn with_service_group<I, S>(
        mut self,
        group: RuntimeLogicalServiceGroup,
        owner_role: RuntimeProcessRole,
        services: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let ownership = RuntimeServiceGroupOwnership::new(group, owner_role, services);
        if let Some(existing) = self
            .service_groups
            .iter_mut()
            .find(|existing| existing.group == ownership.group)
        {
            *existing = ownership;
        } else {
            self.service_groups.push(ownership);
        }
        self.service_groups
            .sort_unstable_by(|left, right| left.group.as_str().cmp(right.group.as_str()));
        self
    }

    /// Replace the cell-scoped service-group directory published for the current cell slice.
    pub fn with_service_group_directory<I>(mut self, service_group_directory: I) -> Self
    where
        I: IntoIterator<Item = RuntimeServiceGroupDirectoryEntry>,
    {
        self.service_group_directory = normalized_service_group_directory(service_group_directory);
        self
    }

    /// Replace the participant registrations published for the current cell slice.
    pub fn with_participants<I>(mut self, participants: I) -> Self
    where
        I: IntoIterator<Item = RuntimeParticipantRegistration>,
    {
        self.participants = normalized_participants(participants);
        self
    }

    /// Replace the recent tombstone history published for the current runtime cell slice.
    pub fn with_tombstone_history<I>(mut self, tombstone_history: I) -> Self
    where
        I: IntoIterator<Item = RuntimeParticipantTombstoneHistoryEntry>,
    {
        self.tombstone_history = normalized_tombstone_history(tombstone_history);
        self
    }
}

fn trimmed_string(value: impl Into<String>) -> String {
    value.into().trim().to_owned()
}

fn trimmed_or_fallback(value: impl Into<String>, fallback: &str) -> String {
    let trimmed = trimmed_string(value);
    if trimmed.is_empty() {
        fallback.to_owned()
    } else {
        trimmed
    }
}

fn trimmed_optional_string(value: impl Into<String>) -> Option<String> {
    let value = trimmed_string(value);
    if value.is_empty() { None } else { Some(value) }
}

fn trimmed_optional_str_matches(left: Option<&str>, right: Option<&str>) -> bool {
    match (
        left.map(str::trim).filter(|value| !value.is_empty()),
        right.map(str::trim).filter(|value| !value.is_empty()),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => true,
    }
}

fn runtime_process_identity_parts(registration_id: &str) -> Option<(&str, &str)> {
    let trimmed = registration_id.trim();
    let (role, node_name) = trimmed.split_once(':')?;
    let role = role.trim();
    let node_name = node_name.trim();
    if role.is_empty() || node_name.is_empty() {
        return None;
    }
    Some((role, node_name))
}

fn runtime_service_group_registration_base_health(
    registration: &RuntimeServiceGroupRegistrationResolution,
) -> bool {
    if registration.readiness.is_some()
        || registration.drain_intent.is_some()
        || registration.lease_freshness.is_some()
    {
        registration.readiness == Some(RuntimeReadinessState::Ready)
            && registration.drain_intent == Some(RuntimeDrainIntent::Serving)
            && registration.lease_freshness == Some(RuntimeLeaseFreshness::Fresh)
    } else {
        registration.healthy
    }
}

fn runtime_service_group_registration_has_invalid_runtime_link(
    registration: &RuntimeServiceGroupRegistrationResolution,
) -> bool {
    if registration.participant_kind.trim() != "runtime_process" {
        return false;
    }

    let normalized_registration_id = trimmed_string(registration.registration_id.clone());
    let Some((expected_role, expected_node_name)) =
        runtime_process_identity_parts(normalized_registration_id.as_str())
    else {
        return true;
    };

    trimmed_string(registration.subject_id.clone()) != normalized_registration_id
        || trimmed_string(registration.role.clone()) != expected_role
        || !trimmed_optional_str_matches(
            registration.node_name.as_deref(),
            Some(expected_node_name),
        )
        || registration
            .lease_registration_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some_and(|lease_registration_id| {
                lease_registration_id != normalized_registration_id
            })
}

fn normalized_string_list<I, S>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut values = values
        .into_iter()
        .map(trimmed_string)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
}

fn normalized_participants<I>(participants: I) -> Vec<RuntimeParticipantRegistration>
where
    I: IntoIterator<Item = RuntimeParticipantRegistration>,
{
    let mut by_registration_id = BTreeMap::new();
    for participant in participants {
        by_registration_id.insert(participant.registration_id.clone(), participant);
    }
    by_registration_id.into_values().collect()
}

fn normalized_service_group_registrations<I>(
    registrations: I,
) -> Vec<RuntimeServiceGroupRegistrationResolution>
where
    I: IntoIterator<Item = RuntimeServiceGroupRegistrationResolution>,
{
    let mut by_registration_id = BTreeMap::new();
    for registration in registrations {
        by_registration_id.insert(registration.registration_id.clone(), registration);
    }
    by_registration_id.into_values().collect()
}

fn normalized_service_group_directory<I>(
    service_group_directory: I,
) -> Vec<RuntimeServiceGroupDirectoryEntry>
where
    I: IntoIterator<Item = RuntimeServiceGroupDirectoryEntry>,
{
    let mut by_group = BTreeMap::new();
    for entry in service_group_directory {
        by_group.insert(entry.group.as_str().to_owned(), entry);
    }
    by_group.into_values().collect()
}

fn normalized_tombstone_history<I>(
    tombstone_history: I,
) -> Vec<RuntimeParticipantTombstoneHistoryEntry>
where
    I: IntoIterator<Item = RuntimeParticipantTombstoneHistoryEntry>,
{
    let mut by_event_id = BTreeMap::new();
    for entry in tombstone_history {
        by_event_id.insert(entry.event_id.clone(), entry);
    }
    let mut entries = by_event_id.into_values().collect::<Vec<_>>();
    entries.sort_unstable_by(|left, right| {
        right
            .tombstoned_at
            .cmp(&left.tombstoned_at)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    entries
}

/// Shared mutable runtime topology snapshot used by the protected reporting surface.
#[derive(Debug, Clone)]
pub struct RuntimeTopologyHandle {
    inner: Arc<StdRwLock<RuntimeTopology>>,
}

impl Default for RuntimeTopologyHandle {
    fn default() -> Self {
        Self::new(RuntimeTopology::default())
    }
}

impl RuntimeTopologyHandle {
    /// Build a new shared topology handle from one initial snapshot.
    pub fn new(topology: RuntimeTopology) -> Self {
        Self {
            inner: Arc::new(StdRwLock::new(topology)),
        }
    }

    /// Clone the current topology snapshot.
    pub fn snapshot(&self) -> RuntimeTopology {
        self.inner
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    /// Replace the current topology snapshot.
    pub fn replace(&self, topology: RuntimeTopology) {
        *self
            .inner
            .write()
            .unwrap_or_else(|poison| poison.into_inner()) = topology;
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use time::OffsetDateTime;

    use super::{
        RuntimeDrainIntent, RuntimeLeaseFreshness, RuntimeLogicalServiceGroup,
        RuntimeReadinessState, RuntimeServiceGroupConflictState, RuntimeServiceGroupDirectoryEntry,
        RuntimeServiceGroupQuarantineReason, RuntimeServiceGroupRegistrationResolution,
    };

    #[test]
    fn service_group_directory_entry_reports_healthy_conflict_quarantine_summary() {
        let registered_at = OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap_or_else(|error| panic!("{error}"));
        let entry = RuntimeServiceGroupDirectoryEntry::new(RuntimeLogicalServiceGroup::Edge)
            .with_conflict_state(RuntimeServiceGroupConflictState::MultipleHealthyRegistrations)
            .with_registrations([
                RuntimeServiceGroupRegistrationResolution::new(
                    "all_in_one:node-a",
                    "runtime_process",
                    "all_in_one:node-a",
                    "all_in_one",
                    registered_at,
                    false,
                )
                .with_lease_registration_id("all_in_one:node-a")
                .with_readiness(RuntimeReadinessState::Ready)
                .with_drain_intent(RuntimeDrainIntent::Serving)
                .with_lease_freshness(RuntimeLeaseFreshness::Fresh),
                RuntimeServiceGroupRegistrationResolution::new(
                    "all_in_one:node-b",
                    "runtime_process",
                    "all_in_one:node-b",
                    "all_in_one",
                    registered_at,
                    false,
                )
                .with_lease_registration_id("all_in_one:node-b")
                .with_readiness(RuntimeReadinessState::Ready)
                .with_drain_intent(RuntimeDrainIntent::Serving)
                .with_lease_freshness(RuntimeLeaseFreshness::Fresh),
            ]);

        assert_eq!(
            serde_json::to_value(entry.quarantine_summaries)
                .unwrap_or_else(|error| panic!("{error}")),
            json!([{
                "reason": "healthy_conflict",
                "registration_count": 2
            }])
        );
    }

    #[test]
    fn service_group_directory_entry_reports_invalid_link_quarantine_summary() {
        let registered_at = OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap_or_else(|error| panic!("{error}"));
        let entry =
            RuntimeServiceGroupDirectoryEntry::new(RuntimeLogicalServiceGroup::DataAndMessaging)
                .with_conflict_state(RuntimeServiceGroupConflictState::NoConflict)
                .with_registrations([RuntimeServiceGroupRegistrationResolution::new(
                    "controller:node-b",
                    "runtime_process",
                    "controller:node-b",
                    "controller",
                    registered_at,
                    false,
                )
                .with_node_name("node-b")
                .with_lease_registration_id("worker:node-b")
                .with_readiness(RuntimeReadinessState::Ready)
                .with_drain_intent(RuntimeDrainIntent::Draining)
                .with_lease_freshness(RuntimeLeaseFreshness::Expired)]);

        assert_eq!(
            serde_json::to_value(entry.quarantine_summaries)
                .unwrap_or_else(|error| panic!("{error}")),
            json!([{
                "reason": "invalid_runtime_registration_link",
                "registration_count": 1
            }])
        );
    }

    #[test]
    fn service_group_directory_entry_reports_both_quarantine_reasons() {
        let registered_at = OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap_or_else(|error| panic!("{error}"));
        let entry = RuntimeServiceGroupDirectoryEntry::new(RuntimeLogicalServiceGroup::Control)
            .with_conflict_state(RuntimeServiceGroupConflictState::MultipleHealthyRegistrations)
            .with_registrations([
                RuntimeServiceGroupRegistrationResolution::new(
                    "controller:node-a",
                    "runtime_process",
                    "controller:node-a",
                    "controller",
                    registered_at,
                    false,
                )
                .with_node_name("node-a")
                .with_lease_registration_id("controller:node-a")
                .with_readiness(RuntimeReadinessState::Ready)
                .with_drain_intent(RuntimeDrainIntent::Serving)
                .with_lease_freshness(RuntimeLeaseFreshness::Fresh),
                RuntimeServiceGroupRegistrationResolution::new(
                    "controller:node-c",
                    "runtime_process",
                    "controller:node-c",
                    "controller",
                    registered_at,
                    false,
                )
                .with_node_name("node-c")
                .with_lease_registration_id("controller:node-c")
                .with_readiness(RuntimeReadinessState::Ready)
                .with_drain_intent(RuntimeDrainIntent::Serving)
                .with_lease_freshness(RuntimeLeaseFreshness::Fresh),
                RuntimeServiceGroupRegistrationResolution::new(
                    "controller:node-b",
                    "runtime_process",
                    "controller:node-b",
                    "controller",
                    registered_at,
                    false,
                )
                .with_node_name("node-b")
                .with_lease_registration_id("worker:node-b")
                .with_readiness(RuntimeReadinessState::Ready)
                .with_drain_intent(RuntimeDrainIntent::Draining)
                .with_lease_freshness(RuntimeLeaseFreshness::Expired),
            ]);

        assert_eq!(
            entry.quarantine_summaries,
            vec![
                super::RuntimeServiceGroupQuarantineSummary::new(
                    RuntimeServiceGroupQuarantineReason::InvalidRuntimeRegistrationLink,
                    1,
                ),
                super::RuntimeServiceGroupQuarantineSummary::new(
                    RuntimeServiceGroupQuarantineReason::HealthyConflict,
                    2,
                ),
            ]
        );
    }
}
