//! Reusable cell-directory and participant-registration collection abstractions.
//!
//! Phase 1 keeps region, cell, and participant registration state file-backed via
//! [`DocumentStore<T>`](crate::document::DocumentStore) while introducing a
//! narrow reusable substrate that later registry and distribution lanes can
//! build on without coupling directly to one concrete adapter.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use uhost_core::{ErrorCode, PlatformError, Result};

use crate::document::{
    DocumentChange, DocumentChangePage, DocumentCursor, DocumentSnapshotCheckpoint, DocumentStore,
    StoredDocument,
};
use crate::lease::{
    LeaseDrainIntent, LeaseFreshness, LeaseReadiness, LeaseRegistrationCollection,
    LeaseRegistrationCursor, LeaseRegistrationRecord, LeaseRegistrationSnapshotCheckpoint,
};
use crate::metadata::MetadataCollection;
use crate::workflow::{WorkflowInstance, WorkflowStep};

/// Boxed future returned by cell-directory backends.
pub type CellDirectoryResultFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Stable cursor used to consume deterministic cell-directory changes.
pub type CellDirectoryCursor = DocumentCursor;

/// One deterministic cell-directory mutation snapshot.
pub type CellDirectoryChange = DocumentChange<CellDirectoryRecord>;

/// One ordered page of deterministic cell-directory changes.
pub type CellDirectoryChangePage = DocumentChangePage<CellDirectoryRecord>;

/// Point-in-time checkpoint used to reseed cell-directory consumers after
/// change-feed compaction.
pub type CellDirectorySnapshotCheckpoint = DocumentSnapshotCheckpoint<CellDirectoryRecord>;

/// Durable region membership carried by one cell directory record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionDirectoryRecord {
    /// Stable region identifier.
    pub region_id: String,
    /// Human-meaningful region name used by operators and reports.
    pub region_name: String,
}

impl RegionDirectoryRecord {
    /// Build one region directory record.
    pub fn new(region_id: impl Into<String>, region_name: impl Into<String>) -> Self {
        Self {
            region_id: trimmed_string(region_id),
            region_name: trimmed_string(region_name),
        }
    }
}

/// Lease snapshot reconciled into one durable cell participant registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellParticipantLeaseState {
    /// Most recent successful lease renewal time.
    pub renewed_at: OffsetDateTime,
    /// Lease expiration time.
    pub expires_at: OffsetDateTime,
    /// Requested lease duration in whole seconds.
    pub duration_seconds: u32,
    /// Computed lease freshness state.
    pub freshness: LeaseFreshness,
}

impl CellParticipantLeaseState {
    /// Build one cell participant lease snapshot.
    pub fn new(
        renewed_at: OffsetDateTime,
        expires_at: OffsetDateTime,
        duration_seconds: u32,
        freshness: LeaseFreshness,
    ) -> Self {
        Self {
            renewed_at,
            expires_at,
            duration_seconds: duration_seconds.max(1),
            freshness,
        }
    }
}

/// Source used to derive effective participant lease freshness and associated availability state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CellParticipantLeaseSource {
    /// State came from a currently linked lease registration.
    LinkedRegistration,
    /// State was derived from previously published participant state because no linked lease registration was available.
    #[default]
    PublishedStateFallback,
}

/// Explicit reason why lease safety degraded the effective participant state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellParticipantDegradedReason {
    /// Effective drain was forced because the lease is nearing expiration.
    LeaseStale,
    /// Effective drain was forced because the lease has expired.
    LeaseExpired,
}

/// Explicit graceful-drain phase carried independently from lease freshness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CellParticipantDrainPhase {
    /// Participant is serving normally with no graceful drain in progress.
    #[default]
    Serving,
    /// Participant requested drain and now waits for a replacement to take over.
    TakeoverPending,
    /// Participant requested drain and a replacement acknowledged takeover.
    TakeoverAcknowledged,
}

/// Reconciled readiness, drain, and lease state for one durable cell participant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellParticipantState {
    /// Published readiness state.
    pub readiness: LeaseReadiness,
    /// Effective drain intent after lease-safety degradation has been applied.
    pub drain_intent: LeaseDrainIntent,
    /// Originally published drain intent before lease-safety degradation forced draining.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_drain_intent: Option<LeaseDrainIntent>,
    /// Explicit graceful-drain phase tracked independently from lease freshness degradation.
    #[serde(default)]
    pub drain_phase: CellParticipantDrainPhase,
    /// Registration currently acknowledged as the takeover target for this drain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takeover_registration_id: Option<String>,
    /// Timestamp when the replacement registration acknowledged takeover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takeover_acknowledged_at: Option<OffsetDateTime>,
    /// Explicit reason when lease safety degraded the effective state beyond the published drain intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded_reason: Option<CellParticipantDegradedReason>,
    /// Source used to derive effective lease freshness and associated availability state.
    #[serde(default)]
    pub lease_source: CellParticipantLeaseSource,
    /// Current lease snapshot.
    pub lease: CellParticipantLeaseState,
}

impl CellParticipantState {
    /// Build one reconciled cell participant state snapshot.
    pub fn new(
        readiness: LeaseReadiness,
        drain_intent: LeaseDrainIntent,
        lease: CellParticipantLeaseState,
    ) -> Self {
        let mut state = Self {
            readiness,
            drain_intent,
            published_drain_intent: Some(drain_intent),
            drain_phase: CellParticipantDrainPhase::Serving,
            takeover_registration_id: None,
            takeover_acknowledged_at: None,
            degraded_reason: None,
            lease_source: CellParticipantLeaseSource::PublishedStateFallback,
            lease,
        };
        state.recompute_derived_state();
        state
    }

    /// Return the originally published drain intent, falling back to the effective value for legacy records.
    pub fn published_drain_intent(&self) -> LeaseDrainIntent {
        self.published_drain_intent.unwrap_or(self.drain_intent)
    }

    fn recompute_degraded_reason(&mut self) {
        self.degraded_reason = degraded_reason_for_effective_state(
            self.drain_intent,
            self.published_drain_intent(),
            self.lease.freshness,
        );
    }

    fn recompute_drain_phase(&mut self) {
        if self.published_drain_intent() != LeaseDrainIntent::Draining {
            self.drain_phase = CellParticipantDrainPhase::Serving;
            self.takeover_registration_id = None;
            self.takeover_acknowledged_at = None;
            return;
        }

        if self.takeover_registration_id.is_some() && self.takeover_acknowledged_at.is_some() {
            self.drain_phase = CellParticipantDrainPhase::TakeoverAcknowledged;
        } else {
            self.drain_phase = CellParticipantDrainPhase::TakeoverPending;
            self.takeover_registration_id = None;
            self.takeover_acknowledged_at = None;
        }
    }

    fn recompute_derived_state(&mut self) {
        self.recompute_degraded_reason();
        self.recompute_drain_phase();
    }

    /// Override the originally published drain intent when lease safety rules degrade the effective state.
    pub fn with_published_drain_intent(mut self, published_drain_intent: LeaseDrainIntent) -> Self {
        self.published_drain_intent = Some(published_drain_intent);
        self.recompute_derived_state();
        self
    }

    /// Override the source used to derive effective participant state.
    pub fn with_lease_source(mut self, lease_source: CellParticipantLeaseSource) -> Self {
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

/// Durable reconciliation metadata carried by one participant registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellParticipantReconciliationState {
    /// Timestamp of the most recent participant reconciliation pass.
    pub last_reconciled_at: OffsetDateTime,
    /// Timestamp when the participant first entered a stale or expired state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_since: Option<OffsetDateTime>,
    /// Linked cleanup workflow identifier when one has been created for this participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_workflow_id: Option<String>,
}

impl CellParticipantReconciliationState {
    /// Build one reconciliation metadata snapshot.
    pub fn new(last_reconciled_at: OffsetDateTime) -> Self {
        Self {
            last_reconciled_at,
            stale_since: None,
            cleanup_workflow_id: None,
        }
    }

    /// Attach the first observed stale timestamp when one exists.
    pub fn with_stale_since(mut self, stale_since: OffsetDateTime) -> Self {
        self.stale_since = Some(stale_since);
        self
    }

    /// Attach the linked cleanup workflow identifier when one exists.
    pub fn with_cleanup_workflow_id(mut self, cleanup_workflow_id: impl Into<String>) -> Self {
        self.cleanup_workflow_id = trimmed_optional_string(cleanup_workflow_id);
        self
    }
}

/// Cleanup action requested for one long-stale participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleParticipantCleanupAction {
    /// Attempt safe evacuation first and only tombstone when local state is safe.
    EvacuateOrTombstone,
}

/// Local progression stage for one stale participant cleanup workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StaleParticipantCleanupStage {
    /// Workflow exists but still awaits bounded repeated local review.
    #[default]
    PendingReview,
    /// Local repeated review confirmed the peer remains expired and draining.
    PreflightConfirmed,
    /// Local repeated review confirmed operator-visible tombstone eligibility.
    TombstoneEligible,
}

/// Durable route-withdrawal preparation artifact recorded before local evacuation proceeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvacuationRouteWithdrawalArtifact {
    /// Stable artifact identifier.
    pub artifact_id: String,
    /// Participant registration being withdrawn from service-group routing.
    pub source_participant_registration_id: String,
    /// Logical service groups that should stop resolving to the stale participant.
    #[serde(default)]
    pub service_groups: Vec<String>,
    /// Timestamp when the route-withdrawal artifact was first prepared.
    pub prepared_at: OffsetDateTime,
}

impl EvacuationRouteWithdrawalArtifact {
    /// Build one route-withdrawal preparation artifact.
    pub fn new(
        cell_id: impl Into<String>,
        source_participant_registration_id: impl Into<String>,
        service_groups: Vec<String>,
        prepared_at: OffsetDateTime,
    ) -> Self {
        let cell_id = trimmed_string(cell_id);
        let source_participant_registration_id = trimmed_string(source_participant_registration_id);
        Self {
            artifact_id: format!("route-withdrawal:{cell_id}:{source_participant_registration_id}"),
            source_participant_registration_id,
            service_groups: normalized_string_list(service_groups),
            prepared_at,
        }
    }

    fn refresh(
        &mut self,
        cell_id: impl Into<String>,
        source_participant_registration_id: impl Into<String>,
        service_groups: Vec<String>,
    ) {
        let cell_id = trimmed_string(cell_id);
        let source_participant_registration_id = trimmed_string(source_participant_registration_id);
        self.artifact_id =
            format!("route-withdrawal:{cell_id}:{source_participant_registration_id}");
        self.source_participant_registration_id = source_participant_registration_id;
        self.service_groups = normalized_string_list(service_groups);
    }
}

/// Durable target-readiness preparation artifact recorded before local evacuation proceeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvacuationTargetReadinessArtifact {
    /// Stable artifact identifier.
    pub artifact_id: String,
    /// Participant registration being evacuated away from.
    pub source_participant_registration_id: String,
    /// Participant registration selected as the local evacuation target.
    pub target_participant_registration_id: String,
    /// Logical service groups that the selected target must keep ready.
    #[serde(default)]
    pub service_groups: Vec<String>,
    /// Timestamp when the target-readiness artifact was first prepared.
    pub prepared_at: OffsetDateTime,
}

impl EvacuationTargetReadinessArtifact {
    /// Build one target-readiness preparation artifact.
    pub fn new(
        cell_id: impl Into<String>,
        source_participant_registration_id: impl Into<String>,
        target_participant_registration_id: impl Into<String>,
        service_groups: Vec<String>,
        prepared_at: OffsetDateTime,
    ) -> Self {
        let cell_id = trimmed_string(cell_id);
        let source_participant_registration_id = trimmed_string(source_participant_registration_id);
        let target_participant_registration_id = trimmed_string(target_participant_registration_id);
        Self {
            artifact_id: format!(
                "target-readiness:{cell_id}:{source_participant_registration_id}:{target_participant_registration_id}"
            ),
            source_participant_registration_id,
            target_participant_registration_id,
            service_groups: normalized_string_list(service_groups),
            prepared_at,
        }
    }

    fn refresh(
        &mut self,
        cell_id: impl Into<String>,
        source_participant_registration_id: impl Into<String>,
        target_participant_registration_id: impl Into<String>,
        service_groups: Vec<String>,
    ) {
        let cell_id = trimmed_string(cell_id);
        let source_participant_registration_id = trimmed_string(source_participant_registration_id);
        let target_participant_registration_id = trimmed_string(target_participant_registration_id);
        self.artifact_id = format!(
            "target-readiness:{cell_id}:{source_participant_registration_id}:{target_participant_registration_id}"
        );
        self.source_participant_registration_id = source_participant_registration_id;
        self.target_participant_registration_id = target_participant_registration_id;
        self.service_groups = normalized_string_list(service_groups);
    }
}

/// Durable rollback preparation artifact recorded before local evacuation proceeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvacuationRollbackArtifact {
    /// Stable artifact identifier.
    pub artifact_id: String,
    /// Participant registration being evacuated away from.
    pub source_participant_registration_id: String,
    /// Participant registration selected as the temporary local target.
    pub target_participant_registration_id: String,
    /// Logical service groups that should be restored if the evacuation is rolled back.
    #[serde(default)]
    pub service_groups: Vec<String>,
    /// Timestamp when the rollback artifact was first prepared.
    pub prepared_at: OffsetDateTime,
}

impl EvacuationRollbackArtifact {
    /// Build one rollback preparation artifact.
    pub fn new(
        cell_id: impl Into<String>,
        source_participant_registration_id: impl Into<String>,
        target_participant_registration_id: impl Into<String>,
        service_groups: Vec<String>,
        prepared_at: OffsetDateTime,
    ) -> Self {
        let cell_id = trimmed_string(cell_id);
        let source_participant_registration_id = trimmed_string(source_participant_registration_id);
        let target_participant_registration_id = trimmed_string(target_participant_registration_id);
        Self {
            artifact_id: format!(
                "rollback:{cell_id}:{source_participant_registration_id}:{target_participant_registration_id}"
            ),
            source_participant_registration_id,
            target_participant_registration_id,
            service_groups: normalized_string_list(service_groups),
            prepared_at,
        }
    }

    fn refresh(
        &mut self,
        cell_id: impl Into<String>,
        source_participant_registration_id: impl Into<String>,
        target_participant_registration_id: impl Into<String>,
        service_groups: Vec<String>,
    ) {
        let cell_id = trimmed_string(cell_id);
        let source_participant_registration_id = trimmed_string(source_participant_registration_id);
        let target_participant_registration_id = trimmed_string(target_participant_registration_id);
        self.artifact_id = format!(
            "rollback:{cell_id}:{source_participant_registration_id}:{target_participant_registration_id}"
        );
        self.source_participant_registration_id = source_participant_registration_id;
        self.target_participant_registration_id = target_participant_registration_id;
        self.service_groups = normalized_string_list(service_groups);
    }
}

/// Domain-specific state carried by one stale participant cleanup workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleParticipantCleanupWorkflowState {
    /// Cell currently owning the stale participant registration.
    pub cell_id: String,
    /// Participant registration targeted by the cleanup workflow.
    pub participant_registration_id: String,
    /// Participant subject identifier targeted by the cleanup workflow.
    pub participant_subject_id: String,
    /// Participant role targeted by the cleanup workflow.
    pub participant_role: String,
    /// Optional node name associated with the stale participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// Logical service groups currently associated with the stale participant.
    #[serde(default)]
    pub service_groups: Vec<String>,
    /// Optional linked lease-registration identifier associated with the stale participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_registration_id: Option<String>,
    /// Timestamp when the participant first entered the stale or expired state.
    pub stale_since: OffsetDateTime,
    /// Timestamp of the most recent stale observation persisted into the workflow.
    pub last_observed_stale_at: OffsetDateTime,
    /// Current cleanup action requested for the participant.
    pub action: StaleParticipantCleanupAction,
    /// Current bounded local progression stage for the cleanup review.
    #[serde(default)]
    pub stage: StaleParticipantCleanupStage,
    /// Count of local stale observations persisted into this workflow.
    #[serde(default = "default_stale_participant_cleanup_review_observations")]
    pub review_observations: u32,
    /// Timestamp when local repeated review first confirmed cleanup preflight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight_confirmed_at: Option<OffsetDateTime>,
    /// Prepared route-withdrawal artifact for the stale participant when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_withdrawal: Option<EvacuationRouteWithdrawalArtifact>,
    /// Prepared target-readiness artifact for the stale participant when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_readiness: Option<EvacuationTargetReadinessArtifact>,
    /// Prepared rollback artifact for the stale participant when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback: Option<EvacuationRollbackArtifact>,
    /// Timestamp when local repeated review first marked the participant tombstone-eligible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tombstone_eligible_at: Option<OffsetDateTime>,
}

impl StaleParticipantCleanupWorkflowState {
    /// Build one stale participant cleanup workflow state payload.
    pub fn new(
        cell_id: impl Into<String>,
        participant: &CellParticipantRecord,
        stale_since: OffsetDateTime,
        last_observed_stale_at: OffsetDateTime,
    ) -> Self {
        let mut state = Self {
            cell_id: String::new(),
            participant_registration_id: String::new(),
            participant_subject_id: String::new(),
            participant_role: String::new(),
            node_name: None,
            service_groups: Vec::new(),
            lease_registration_id: None,
            stale_since,
            last_observed_stale_at,
            action: StaleParticipantCleanupAction::EvacuateOrTombstone,
            stage: StaleParticipantCleanupStage::PendingReview,
            review_observations: default_stale_participant_cleanup_review_observations(),
            preflight_confirmed_at: None,
            route_withdrawal: None,
            target_readiness: None,
            rollback: None,
            tombstone_eligible_at: None,
        };
        state.refresh(cell_id, participant, stale_since, last_observed_stale_at);
        state
    }

    /// Refresh the participant snapshot persisted into this workflow without changing progression.
    pub fn refresh(
        &mut self,
        cell_id: impl Into<String>,
        participant: &CellParticipantRecord,
        stale_since: OffsetDateTime,
        observed_at: OffsetDateTime,
    ) {
        self.cell_id = trimmed_string(cell_id);
        self.participant_registration_id = trimmed_string(participant.registration_id.clone());
        self.participant_subject_id = trimmed_string(participant.subject_id.clone());
        self.participant_role = trimmed_string(participant.role.clone());
        self.node_name = participant.node_name.clone();
        self.service_groups = normalized_string_list(participant.service_groups.iter().cloned());
        self.lease_registration_id = participant.lease_registration_id.clone();
        self.stale_since = stale_since;
        self.last_observed_stale_at = observed_at;
        self.action = StaleParticipantCleanupAction::EvacuateOrTombstone;
    }

    /// Persist one additional local stale observation for this workflow.
    pub fn note_stale_observation(&mut self, observed_at: OffsetDateTime) {
        self.last_observed_stale_at = observed_at;
        self.review_observations = self.review_observations.saturating_add(1).max(1);
    }

    /// Ensure route-withdrawal, target-readiness, and rollback artifacts exist for local evacuation preparation.
    pub fn prepare_evacuation_artifacts(
        &mut self,
        target_participant_registration_id: impl Into<String>,
        prepared_at: OffsetDateTime,
    ) {
        let cell_id = self.cell_id.clone();
        let source_participant_registration_id = self.participant_registration_id.clone();
        let target_participant_registration_id = trimmed_string(target_participant_registration_id);
        let service_groups = normalized_string_list(self.service_groups.iter().cloned());

        match self.route_withdrawal.as_mut() {
            Some(artifact) => artifact.refresh(
                cell_id.clone(),
                source_participant_registration_id.clone(),
                service_groups.clone(),
            ),
            None => {
                self.route_withdrawal = Some(EvacuationRouteWithdrawalArtifact::new(
                    cell_id.clone(),
                    source_participant_registration_id.clone(),
                    service_groups.clone(),
                    prepared_at,
                ));
            }
        }

        match self.target_readiness.as_mut() {
            Some(artifact) => artifact.refresh(
                cell_id.clone(),
                source_participant_registration_id.clone(),
                target_participant_registration_id.clone(),
                service_groups.clone(),
            ),
            None => {
                self.target_readiness = Some(EvacuationTargetReadinessArtifact::new(
                    cell_id.clone(),
                    source_participant_registration_id.clone(),
                    target_participant_registration_id.clone(),
                    service_groups.clone(),
                    prepared_at,
                ));
            }
        }

        match self.rollback.as_mut() {
            Some(artifact) => artifact.refresh(
                cell_id,
                source_participant_registration_id,
                target_participant_registration_id,
                service_groups,
            ),
            None => {
                self.rollback = Some(EvacuationRollbackArtifact::new(
                    self.cell_id.clone(),
                    self.participant_registration_id.clone(),
                    trimmed_string(target_participant_registration_id),
                    self.service_groups.clone(),
                    prepared_at,
                ));
            }
        }
    }

    /// Mark the cleanup workflow as locally preflight-confirmed.
    pub fn mark_preflight_confirmed(&mut self, observed_at: OffsetDateTime) {
        self.stage = StaleParticipantCleanupStage::PreflightConfirmed;
        if self.preflight_confirmed_at.is_none() {
            self.preflight_confirmed_at = Some(observed_at);
        }
    }

    /// Mark the cleanup workflow as locally tombstone-eligible.
    pub fn mark_tombstone_eligible(&mut self, observed_at: OffsetDateTime) {
        self.stage = StaleParticipantCleanupStage::TombstoneEligible;
        if self.preflight_confirmed_at.is_none() {
            self.preflight_confirmed_at = Some(observed_at);
        }
        if self.tombstone_eligible_at.is_none() {
            self.tombstone_eligible_at = Some(observed_at);
        }
    }
}

/// Durable history record preserved after one operator-approved participant tombstone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantTombstoneHistoryRecord {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// Logical service groups owned by the removed participant.
    #[serde(default)]
    pub service_groups: Vec<String>,
    /// Linked cleanup workflow identifier that authorized the destructive mutation.
    pub cleanup_workflow_id: String,
    /// Count of stale observations that led to the operator-visible tombstone decision.
    pub review_observations: u32,
    /// Timestamp when the participant first entered the stale or expired state.
    pub stale_since: OffsetDateTime,
    /// Timestamp when local repeated review first confirmed cleanup preflight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight_confirmed_at: Option<OffsetDateTime>,
    /// Timestamp when local repeated review first marked the participant tombstone-eligible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_registration_id: Option<String>,
    /// Originally published drain intent before lease-safety degradation forced draining at tombstone time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_drain_intent: Option<LeaseDrainIntent>,
    /// Explicit reason when lease safety degraded the effective state beyond the published drain intent at tombstone time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded_reason: Option<CellParticipantDegradedReason>,
    /// Source used to derive effective lease freshness and associated availability state at tombstone time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_source: Option<CellParticipantLeaseSource>,
    /// Whether the participant was removed from the live cell directory.
    pub removed_from_cell_directory: bool,
    /// Whether the linked lease registration was soft-deleted.
    pub lease_registration_soft_deleted: bool,
    /// Whether the linked cleanup workflow was soft-deleted after completion.
    pub cleanup_workflow_soft_deleted: bool,
}

impl ParticipantTombstoneHistoryRecord {
    /// Build one durable participant tombstone history record.
    pub fn new(
        event_id: impl Into<String>,
        participant: &CellParticipantRecord,
        cleanup_workflow_id: impl Into<String>,
        tombstoned_at: OffsetDateTime,
        actor_subject: impl Into<String>,
        actor_type: impl Into<String>,
        correlation_id: impl Into<String>,
    ) -> Self {
        let (published_drain_intent, degraded_reason, lease_source) = participant
            .state
            .as_ref()
            .map(|state| {
                (
                    Some(state.published_drain_intent()),
                    state.degraded_reason,
                    Some(state.lease_source),
                )
            })
            .unwrap_or((None, None, None));
        Self {
            event_id: trimmed_string(event_id),
            cell_id: String::new(),
            cell_name: String::new(),
            region_id: String::new(),
            region_name: String::new(),
            participant_registration_id: trimmed_string(participant.registration_id.clone()),
            participant_kind: trimmed_string(participant.participant_kind.clone()),
            participant_subject_id: trimmed_string(participant.subject_id.clone()),
            participant_role: trimmed_string(participant.role.clone()),
            node_name: participant.node_name.as_ref().and_then(|value| {
                let value = trimmed_string(value.clone());
                (!value.is_empty()).then_some(value)
            }),
            service_groups: normalized_string_list(participant.service_groups.iter().cloned()),
            cleanup_workflow_id: trimmed_string(cleanup_workflow_id),
            review_observations: default_stale_participant_cleanup_review_observations(),
            stale_since: tombstoned_at,
            preflight_confirmed_at: None,
            tombstone_eligible_at: None,
            tombstoned_at,
            actor_subject: trimmed_string(actor_subject),
            actor_type: trimmed_string(actor_type),
            correlation_id: trimmed_string(correlation_id),
            lease_registration_id: participant
                .lease_registration_id
                .as_ref()
                .and_then(|value| {
                    let value = trimmed_string(value.clone());
                    (!value.is_empty()).then_some(value)
                }),
            published_drain_intent,
            degraded_reason,
            lease_source,
            removed_from_cell_directory: true,
            lease_registration_soft_deleted: false,
            cleanup_workflow_soft_deleted: false,
        }
    }

    /// Attach the cell and region context active at mutation time.
    pub fn with_cell_context(
        mut self,
        cell_id: impl Into<String>,
        cell_name: impl Into<String>,
        region: &RegionDirectoryRecord,
    ) -> Self {
        self.cell_id = trimmed_string(cell_id);
        self.cell_name = trimmed_string(cell_name);
        self.region_id = trimmed_string(region.region_id.clone());
        self.region_name = trimmed_string(region.region_name.clone());
        self
    }

    /// Attach the bounded cleanup review data recorded before destructive deletion.
    pub fn with_cleanup_review(
        mut self,
        review_observations: u32,
        stale_since: OffsetDateTime,
        preflight_confirmed_at: Option<OffsetDateTime>,
        tombstone_eligible_at: Option<OffsetDateTime>,
    ) -> Self {
        self.review_observations = review_observations.max(1);
        self.stale_since = stale_since;
        self.preflight_confirmed_at = preflight_confirmed_at;
        self.tombstone_eligible_at = tombstone_eligible_at;
        self
    }

    /// Attach the final mutation result flags recorded for the tombstone.
    pub fn with_mutation_result(
        mut self,
        removed_from_cell_directory: bool,
        lease_registration_soft_deleted: bool,
        cleanup_workflow_soft_deleted: bool,
    ) -> Self {
        self.removed_from_cell_directory = removed_from_cell_directory;
        self.lease_registration_soft_deleted = lease_registration_soft_deleted;
        self.cleanup_workflow_soft_deleted = cleanup_workflow_soft_deleted;
        self
    }
}

/// File-backed durable history collection for completed participant tombstones.
pub type ParticipantTombstoneHistoryCollection = DocumentStore<ParticipantTombstoneHistoryRecord>;

fn default_stale_participant_cleanup_review_observations() -> u32 {
    1
}

/// Return the stable cleanup workflow identifier for one stale participant.
pub fn stale_participant_cleanup_workflow_id(
    cell_id: impl Into<String>,
    participant_registration_id: impl Into<String>,
) -> String {
    format!(
        "stale-participant-cleanup:{}:{}",
        trimmed_string(cell_id),
        trimmed_string(participant_registration_id),
    )
}

/// Build one durable stale participant cleanup workflow.
pub fn stale_participant_cleanup_workflow(
    cell_id: impl Into<String>,
    participant: &CellParticipantRecord,
    stale_since: OffsetDateTime,
    observed_at: OffsetDateTime,
) -> WorkflowInstance<StaleParticipantCleanupWorkflowState> {
    let cell_id = trimmed_string(cell_id);
    let workflow_id =
        stale_participant_cleanup_workflow_id(cell_id.clone(), participant.registration_id.clone());
    WorkflowInstance::new(
        workflow_id,
        "runtime.participant.cleanup.v1",
        "cell_participant",
        participant.registration_id.clone(),
        StaleParticipantCleanupWorkflowState::new(cell_id, participant, stale_since, observed_at),
        vec![
            WorkflowStep::new("confirm_stale_peer", 0),
            WorkflowStep::new("prepare_evacuation", 1),
            WorkflowStep::new("tombstone_participant", 2),
        ],
    )
}

/// Durable participant registration inside one cell directory record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellParticipantRecord {
    /// Stable participant registration identifier.
    pub registration_id: String,
    /// Broad participant family (`runtime_process`, `service_group`, etc.).
    pub participant_kind: String,
    /// Stable subject identifier bound to this participant.
    pub subject_id: String,
    /// Role or ownership label carried by the participant.
    pub role: String,
    /// Optional node name associated with the participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// Logical service groups currently owned by this participant.
    #[serde(default)]
    pub service_groups: Vec<String>,
    /// Optional lease-backed registration identifier associated with the participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_registration_id: Option<String>,
    /// Optional reconciled readiness, drain, and lease snapshot for this participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<CellParticipantState>,
    /// Optional stale or reconciliation metadata for this participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciliation: Option<CellParticipantReconciliationState>,
    /// Timestamp when the participant registration was published.
    pub registered_at: OffsetDateTime,
}

impl CellParticipantRecord {
    /// Build one participant registration record.
    pub fn new(
        registration_id: impl Into<String>,
        participant_kind: impl Into<String>,
        subject_id: impl Into<String>,
        role: impl Into<String>,
    ) -> Self {
        Self {
            registration_id: trimmed_string(registration_id),
            participant_kind: trimmed_string(participant_kind),
            subject_id: trimmed_string(subject_id),
            role: trimmed_string(role),
            node_name: None,
            service_groups: Vec::new(),
            lease_registration_id: None,
            state: None,
            reconciliation: None,
            registered_at: OffsetDateTime::now_utc(),
        }
    }

    /// Attach an optional node name when constructing a participant.
    pub fn with_node_name(mut self, node_name: impl Into<String>) -> Self {
        self.node_name = trimmed_optional_string(node_name);
        self
    }

    /// Attach owned logical service groups when constructing a participant.
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

    /// Attach a reconciled readiness, drain, and lease snapshot when one exists.
    pub fn with_state(mut self, state: CellParticipantState) -> Self {
        self.state = Some(state);
        self
    }

    /// Attach stale or reconciliation metadata when one exists.
    pub fn with_reconciliation(
        mut self,
        reconciliation: CellParticipantReconciliationState,
    ) -> Self {
        self.reconciliation = Some(reconciliation);
        self
    }
}

/// Durable cell directory record containing one cell, its region, and registered participants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellDirectoryRecord {
    /// Stable cell identifier.
    pub cell_id: String,
    /// Human-meaningful cell name used by operators and reports.
    pub cell_name: String,
    /// Region membership for the cell.
    pub region: RegionDirectoryRecord,
    /// Registered participants currently associated with this cell.
    #[serde(default)]
    pub participants: Vec<CellParticipantRecord>,
    /// Timestamp when this cell record was first published.
    pub registered_at: OffsetDateTime,
    /// Timestamp when this cell record was most recently updated.
    pub updated_at: OffsetDateTime,
}

impl CellDirectoryRecord {
    /// Build one cell directory record.
    pub fn new(
        cell_id: impl Into<String>,
        cell_name: impl Into<String>,
        region: RegionDirectoryRecord,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            cell_id: trimmed_string(cell_id),
            cell_name: trimmed_string(cell_name),
            region,
            participants: Vec::new(),
            registered_at: now,
            updated_at: now,
        }
    }

    /// Replace the published cell name.
    pub fn set_cell_name(&mut self, cell_name: impl Into<String>) {
        self.cell_name = trimmed_string(cell_name);
        self.touch();
    }

    /// Replace the published region membership.
    pub fn set_region(&mut self, region: RegionDirectoryRecord) {
        self.region = region;
        self.touch();
    }

    /// Attach one participant when constructing a record.
    pub fn with_participant(mut self, participant: CellParticipantRecord) -> Self {
        self.upsert_participant(participant);
        self
    }

    /// Insert or replace one participant registration by registration identifier.
    pub fn upsert_participant(&mut self, participant: CellParticipantRecord) {
        let mut by_registration_id = self
            .participants
            .drain(..)
            .map(|existing| (existing.registration_id.clone(), existing))
            .collect::<BTreeMap<_, _>>();
        by_registration_id.insert(participant.registration_id.clone(), participant);
        self.participants = by_registration_id.into_values().collect();
        self.touch();
    }

    /// Remove one participant registration by registration identifier.
    pub fn remove_participant(&mut self, participant_registration_id: &str) -> bool {
        let original_len = self.participants.len();
        self.participants
            .retain(|participant| participant.registration_id != participant_registration_id);
        let removed = self.participants.len() != original_len;
        if removed {
            self.touch();
        }
        removed
    }

    fn touch(&mut self) {
        self.updated_at = OffsetDateTime::now_utc();
    }
}

/// Coordination model used when one bounded context is resolved across cells or regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BoundedContextCoordinationModel {
    /// Exactly one healthy writer is expected for the whole region at a time.
    #[default]
    ActivePassiveRegional,
    /// Multiple healthy readers may exist, but writes still funnel through one authority.
    ActiveActiveReadOnly,
    /// Multiple healthy registrations are safe when each one owns a distinct shard home.
    ActiveActiveShardScoped,
    /// Multiple healthy registrations are safe because writes are sequenced through quorum.
    ActiveActiveConsensus,
    /// Multiple healthy registrations are safe because operations are commutative at the resource layer.
    ActiveActiveCommutative,
}

impl BoundedContextCoordinationModel {
    /// Whether the registry should treat multiple healthy registrations as an expected posture.
    pub const fn allows_parallel_healthy_registrations(self) -> bool {
        !matches!(self, Self::ActivePassiveRegional)
    }
}

/// Narrowest ownership unit that must stay exclusive for one bounded context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BoundedContextOwnershipScope {
    /// One writer owns the whole regional context.
    #[default]
    Region,
    /// Ownership is exclusive per cell.
    Cell,
    /// Ownership is exclusive per service shard or home assignment.
    ServiceShard,
    /// Ownership is exclusive per individual resource object.
    Resource,
}

/// Durable active-active safety policy attached to one bounded context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BoundedContextSafetyPolicy {
    /// Coordination model that describes whether parallel healthy registrations are safe.
    pub coordination_model: BoundedContextCoordinationModel,
    /// Narrowest ownership unit that must remain exclusive when the context is not fully commutative.
    pub ownership_scope: BoundedContextOwnershipScope,
    /// Whether safe mutation handoff requires lease or fencing tokens.
    #[serde(default)]
    pub requires_fencing: bool,
    /// Whether safe mutation progress depends on quorum or consensus evidence.
    #[serde(default)]
    pub requires_quorum: bool,
    /// Operator-readable notes that explain the safety choice.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl BoundedContextSafetyPolicy {
    /// Build one bounded-context safety policy with defaults derived from the coordination model.
    pub fn new(coordination_model: BoundedContextCoordinationModel) -> Self {
        Self {
            coordination_model,
            ownership_scope: default_ownership_scope_for_coordination_model(coordination_model),
            requires_fencing: false,
            requires_quorum: false,
            notes: Vec::new(),
        }
    }

    /// Override the ownership scope that must remain exclusive for safe operation.
    pub fn with_ownership_scope(mut self, ownership_scope: BoundedContextOwnershipScope) -> Self {
        self.ownership_scope = ownership_scope;
        self
    }

    /// Declare whether this context requires explicit fencing on handoff.
    pub fn with_fencing_requirement(mut self, requires_fencing: bool) -> Self {
        self.requires_fencing = requires_fencing;
        self
    }

    /// Declare whether this context requires quorum evidence before mutation admission.
    pub fn with_quorum_requirement(mut self, requires_quorum: bool) -> Self {
        self.requires_quorum = requires_quorum;
        self
    }

    /// Attach normalized operator-readable notes.
    pub fn with_notes<I, S>(mut self, notes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.notes = normalized_string_list(notes);
        self
    }

    /// Whether this policy permits more than one healthy registration to resolve simultaneously.
    pub const fn allows_parallel_healthy_registrations(&self) -> bool {
        self.coordination_model
            .allows_parallel_healthy_registrations()
    }
}

/// Durable registry row defining active-active safety posture for one bounded-context key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedContextSafetyRecord {
    /// Stable bounded-context identifier.
    ///
    /// The current registry uses logical service-group identifiers here until
    /// first-class service-instance and shard records land.
    pub context_id: String,
    /// Safety policy applied to that bounded context.
    pub policy: BoundedContextSafetyPolicy,
    /// Timestamp when this row was last updated.
    pub updated_at: OffsetDateTime,
}

impl BoundedContextSafetyRecord {
    /// Build one bounded-context safety row.
    pub fn new(context_id: impl Into<String>, policy: BoundedContextSafetyPolicy) -> Self {
        Self {
            context_id: trimmed_string(context_id),
            policy,
            updated_at: OffsetDateTime::now_utc(),
        }
    }
}

/// File-backed durable collection for bounded-context active-active safety rows.
pub type BoundedContextSafetyMatrixCollection = DocumentStore<BoundedContextSafetyRecord>;

/// Conflict state recorded for one logical service-group resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CellServiceGroupConflictState {
    /// No conflicting healthy registrations were observed for the group.
    #[default]
    NoConflict,
    /// Multiple healthy registrations currently claim the same logical group.
    MultipleHealthyRegistrations,
}

/// One participant registration projected into one logical service-group directory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellServiceGroupRegistrationResolution {
    /// Stable participant registration identifier.
    pub registration_id: String,
    /// Broad participant family (`runtime_process`, `service_group`, etc.).
    pub participant_kind: String,
    /// Stable subject identifier associated with the participant.
    pub subject_id: String,
    /// Role or ownership label carried by the participant.
    pub role: String,
    /// Optional node name associated with the participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// Optional linked lease-registration identifier associated with the participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_registration_id: Option<String>,
    /// Timestamp when the participant registration was published.
    pub registered_at: OffsetDateTime,
    /// Optional published readiness state when a reconciled participant state exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness: Option<LeaseReadiness>,
    /// Optional effective drain intent when a reconciled participant state exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_intent: Option<LeaseDrainIntent>,
    /// Optional graceful-drain phase when a reconciled participant state exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_phase: Option<CellParticipantDrainPhase>,
    /// Optional replacement registration that acknowledged takeover for this participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takeover_registration_id: Option<String>,
    /// Optional timestamp when the replacement registration acknowledged takeover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takeover_acknowledged_at: Option<OffsetDateTime>,
    /// Optional effective lease freshness when a reconciled participant state exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_freshness: Option<LeaseFreshness>,
    /// Whether the participant currently resolves as healthy for this logical group.
    #[serde(default)]
    pub healthy: bool,
}

impl CellServiceGroupRegistrationResolution {
    /// Project one cell participant into one logical service-group resolution record.
    pub fn from_participant(participant: &CellParticipantRecord) -> Self {
        let state = participant.state.as_ref();
        let readiness = state.map(|state| state.readiness);
        let drain_intent = state.map(|state| state.drain_intent);
        let drain_phase = state.map(|state| state.drain_phase);
        let takeover_registration_id =
            state.and_then(|state| state.takeover_registration_id.clone());
        let takeover_acknowledged_at = state.and_then(|state| state.takeover_acknowledged_at);
        let lease_freshness = state.map(|state| state.lease.freshness);
        let healthy = state.is_some_and(healthy_cell_service_group_participant_state);
        Self {
            registration_id: trimmed_string(participant.registration_id.clone()),
            participant_kind: trimmed_string(participant.participant_kind.clone()),
            subject_id: trimmed_string(participant.subject_id.clone()),
            role: trimmed_string(participant.role.clone()),
            node_name: participant
                .node_name
                .as_ref()
                .and_then(|value| trimmed_optional_string(value.clone())),
            lease_registration_id: participant
                .lease_registration_id
                .as_ref()
                .and_then(|value| trimmed_optional_string(value.clone())),
            registered_at: participant.registered_at,
            readiness,
            drain_intent,
            drain_phase,
            takeover_registration_id,
            takeover_acknowledged_at,
            lease_freshness,
            healthy,
        }
    }
}

/// One logical service-group resolution entry derived from the current cell directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellServiceGroupDirectoryEntry {
    /// Logical service-group identifier.
    pub group: String,
    /// Active-active safety policy currently applied to this bounded-context slice.
    #[serde(default)]
    pub safety_policy: BoundedContextSafetyPolicy,
    /// Healthy participant registrations currently resolved for this logical group.
    #[serde(default)]
    pub resolved_registration_ids: Vec<String>,
    /// Conflict state derived from the current healthy registrations.
    #[serde(default)]
    pub conflict_state: CellServiceGroupConflictState,
    /// All participant registrations currently advertising this logical group.
    #[serde(default)]
    pub registrations: Vec<CellServiceGroupRegistrationResolution>,
}

impl CellServiceGroupDirectoryEntry {
    /// Build one logical service-group directory entry.
    pub fn new(group: impl Into<String>) -> Self {
        Self {
            group: trimmed_string(group),
            safety_policy: BoundedContextSafetyPolicy::default(),
            resolved_registration_ids: Vec::new(),
            conflict_state: CellServiceGroupConflictState::NoConflict,
            registrations: Vec::new(),
        }
    }

    /// Attach the active-active safety policy that should govern conflict resolution.
    pub fn with_safety_policy(mut self, safety_policy: BoundedContextSafetyPolicy) -> Self {
        self.safety_policy = safety_policy;
        self.recompute_resolution();
        self
    }

    fn upsert_registration(&mut self, registration: CellServiceGroupRegistrationResolution) {
        let mut by_registration_id = self
            .registrations
            .drain(..)
            .map(|existing| (existing.registration_id.clone(), existing))
            .collect::<BTreeMap<_, _>>();
        by_registration_id.insert(registration.registration_id.clone(), registration);
        self.registrations = by_registration_id.into_values().collect();
        self.recompute_resolution();
    }

    fn recompute_resolution(&mut self) {
        for registration in &mut self.registrations {
            registration.healthy = cell_service_group_registration_base_health(registration);
        }

        let quarantined_registration_ids = quarantined_cell_service_group_registration_ids(
            &self.registrations,
            &self.safety_policy,
        );
        for registration in &mut self.registrations {
            if quarantined_registration_ids.contains(registration.registration_id.as_str()) {
                registration.healthy = false;
            }
        }

        self.resolved_registration_ids = self
            .registrations
            .iter()
            .filter(|registration| registration.healthy)
            .map(|registration| registration.registration_id.clone())
            .collect();
        self.conflict_state = if quarantined_registration_ids.is_empty() {
            CellServiceGroupConflictState::NoConflict
        } else {
            CellServiceGroupConflictState::MultipleHealthyRegistrations
        };
    }
}

/// Durable cell-scoped service-group directory derived from the current participant slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellServiceGroupDirectoryRecord {
    /// Stable cell identifier.
    pub cell_id: String,
    /// Human-meaningful cell name used by operators and reports.
    pub cell_name: String,
    /// Region membership for the cell.
    pub region: RegionDirectoryRecord,
    /// Logical service-group directory entries currently resolved for this cell.
    #[serde(default)]
    pub groups: Vec<CellServiceGroupDirectoryEntry>,
    /// Timestamp when this cell-scoped directory was first published.
    pub registered_at: OffsetDateTime,
    /// Timestamp when this cell-scoped directory was most recently updated.
    pub updated_at: OffsetDateTime,
}

impl CellServiceGroupDirectoryRecord {
    /// Build one empty cell-scoped service-group directory record.
    pub fn new(
        cell_id: impl Into<String>,
        cell_name: impl Into<String>,
        region: RegionDirectoryRecord,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            cell_id: trimmed_string(cell_id),
            cell_name: trimmed_string(cell_name),
            region,
            groups: Vec::new(),
            registered_at: now,
            updated_at: now,
        }
    }
}

/// Derive the current cell-scoped service-group directory from the current participant slice.
///
/// Groups without explicit safety rows fall back to an active-passive regional baseline.
pub fn resolve_cell_service_group_directory(
    cell_directory: &CellDirectoryRecord,
) -> CellServiceGroupDirectoryRecord {
    resolve_cell_service_group_directory_with_safety_matrix(
        cell_directory,
        std::iter::empty::<&BoundedContextSafetyRecord>(),
    )
}

/// Derive the current cell-scoped service-group directory using explicit bounded-context safety rows when present.
pub fn resolve_cell_service_group_directory_with_safety_matrix<'a, I>(
    cell_directory: &CellDirectoryRecord,
    safety_records: I,
) -> CellServiceGroupDirectoryRecord
where
    I: IntoIterator<Item = &'a BoundedContextSafetyRecord>,
{
    let safety_by_group = safety_records
        .into_iter()
        .map(|record| {
            (
                trimmed_string(record.context_id.clone()),
                record.policy.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut by_group = BTreeMap::new();
    for participant in &cell_directory.participants {
        let resolution = CellServiceGroupRegistrationResolution::from_participant(participant);
        for group in &participant.service_groups {
            let normalized_group = trimmed_string(group.clone());
            if normalized_group.is_empty() {
                continue;
            }
            let safety_policy = safety_by_group
                .get(normalized_group.as_str())
                .cloned()
                .unwrap_or_default();
            by_group
                .entry(normalized_group.clone())
                .or_insert_with(|| {
                    CellServiceGroupDirectoryEntry::new(normalized_group)
                        .with_safety_policy(safety_policy)
                })
                .upsert_registration(resolution.clone());
        }
    }

    CellServiceGroupDirectoryRecord {
        cell_id: trimmed_string(cell_directory.cell_id.clone()),
        cell_name: trimmed_string(cell_directory.cell_name.clone()),
        region: cell_directory.region.clone(),
        groups: by_group.into_values().collect(),
        registered_at: cell_directory.registered_at,
        updated_at: cell_directory.updated_at,
    }
}

fn default_ownership_scope_for_coordination_model(
    coordination_model: BoundedContextCoordinationModel,
) -> BoundedContextOwnershipScope {
    match coordination_model {
        BoundedContextCoordinationModel::ActivePassiveRegional
        | BoundedContextCoordinationModel::ActiveActiveReadOnly
        | BoundedContextCoordinationModel::ActiveActiveConsensus => {
            BoundedContextOwnershipScope::Region
        }
        BoundedContextCoordinationModel::ActiveActiveShardScoped => {
            BoundedContextOwnershipScope::ServiceShard
        }
        BoundedContextCoordinationModel::ActiveActiveCommutative => {
            BoundedContextOwnershipScope::Resource
        }
    }
}

/// Stable protocol advertised by one service endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ServiceEndpointProtocol {
    /// Plain HTTP endpoint.
    #[default]
    Http,
    /// TLS-terminated HTTP endpoint.
    Https,
    /// gRPC endpoint.
    Grpc,
    /// Raw TCP endpoint.
    Tcp,
    /// Raw UDP endpoint.
    Udp,
}

impl ServiceEndpointProtocol {
    /// Return the stable wire-format tag for this protocol.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Grpc => "grpc",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Return the stable service-instance identifier for one participant-backed service group.
pub fn service_instance_record_id(
    service_group: impl Into<String>,
    participant_registration_id: impl Into<String>,
) -> String {
    format!(
        "{}:{}",
        trimmed_string(service_group),
        trimmed_string(participant_registration_id),
    )
}

/// Durable first-class service-instance record backing service discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInstanceRecord {
    /// Stable service-instance identifier.
    pub service_instance_id: String,
    /// Stable cell identifier owning the instance.
    pub cell_id: String,
    /// Logical service-group identifier served by this instance.
    pub service_group: String,
    /// Stable participant registration currently backing the instance.
    pub participant_registration_id: String,
    /// Optional node name associated with the serving participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// Optional readiness state currently advertised by the backing participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness: Option<LeaseReadiness>,
    /// Optional drain intent currently advertised by the backing participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_intent: Option<LeaseDrainIntent>,
    /// Optional linked lease freshness when the participant published a lease-backed state snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_freshness: Option<LeaseFreshness>,
    /// Monotonic revision of the source projection that produced this record.
    #[serde(default)]
    pub revision: u64,
    /// Stable lease identifiers linked to this instance.
    #[serde(default)]
    pub linked_lease_ids: Vec<String>,
    /// Timestamp when this instance record was first published.
    pub registered_at: OffsetDateTime,
    /// Timestamp when this instance record was most recently updated.
    pub updated_at: OffsetDateTime,
}

impl ServiceInstanceRecord {
    /// Build one empty service-instance record.
    pub fn new(
        service_instance_id: impl Into<String>,
        cell_id: impl Into<String>,
        service_group: impl Into<String>,
        participant_registration_id: impl Into<String>,
        revision: u64,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            service_instance_id: trimmed_string(service_instance_id),
            cell_id: trimmed_string(cell_id),
            service_group: trimmed_string(service_group),
            participant_registration_id: trimmed_string(participant_registration_id),
            node_name: None,
            readiness: None,
            drain_intent: None,
            lease_freshness: None,
            revision,
            linked_lease_ids: Vec::new(),
            registered_at: now,
            updated_at: now,
        }
    }

    /// Project one cell participant and service group into a first-class service instance record.
    pub fn from_participant(
        cell_id: impl Into<String>,
        service_group: impl Into<String>,
        revision: u64,
        participant: &CellParticipantRecord,
    ) -> Self {
        let service_group = trimmed_string(service_group);
        let state = participant.state.as_ref();
        let mut record = Self::new(
            service_instance_record_id(service_group.clone(), participant.registration_id.clone()),
            cell_id,
            service_group,
            participant.registration_id.clone(),
            revision,
        )
        .with_linked_lease_ids(participant.lease_registration_id.iter().cloned());
        record.node_name = participant
            .node_name
            .as_ref()
            .and_then(|value| trimmed_optional_string(value.clone()));
        record.readiness = state.map(|value| value.readiness);
        record.drain_intent = state.map(|value| value.drain_intent);
        record.lease_freshness = state.map(|value| value.lease.freshness);
        record.registered_at = participant.registered_at;
        record.updated_at = participant.registered_at;
        record
    }

    /// Replace the linked lease identifiers for this instance.
    pub fn with_linked_lease_ids<I, S>(mut self, linked_lease_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.linked_lease_ids = normalized_string_list(linked_lease_ids);
        self
    }
}

/// File-backed durable collection of service-instance records.
pub type ServiceInstanceCollection = DocumentStore<ServiceInstanceRecord>;

/// Stable cursor used to consume deterministic service-instance changes.
pub type ServiceInstanceCursor = DocumentCursor;

/// One deterministic service-instance mutation snapshot.
pub type ServiceInstanceChange = DocumentChange<ServiceInstanceRecord>;

/// One ordered page of deterministic service-instance changes.
pub type ServiceInstanceChangePage = DocumentChangePage<ServiceInstanceRecord>;

/// Resolve one first-class service-instance projection per participant-advertised service group.
pub fn resolve_cell_service_instances(
    cell_directory: &CellDirectoryRecord,
    revision: u64,
) -> Vec<ServiceInstanceRecord> {
    let mut by_instance_id = BTreeMap::new();
    for participant in &cell_directory.participants {
        for service_group in &participant.service_groups {
            let normalized_group = trimmed_string(service_group.clone());
            if normalized_group.is_empty() {
                continue;
            }
            let instance = ServiceInstanceRecord::from_participant(
                cell_directory.cell_id.clone(),
                normalized_group,
                revision,
                participant,
            );
            by_instance_id.insert(instance.service_instance_id.clone(), instance);
        }
    }
    by_instance_id.into_values().collect()
}

/// Return the stable service-endpoint identifier for one concrete address publication.
pub fn service_endpoint_record_id(
    service_instance_id: impl Into<String>,
    protocol: ServiceEndpointProtocol,
    address: impl Into<String>,
) -> String {
    format!(
        "{}:{}:{}",
        trimmed_string(service_instance_id),
        protocol.as_str(),
        trimmed_string(address),
    )
}

/// Durable first-class service-endpoint record backing service discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEndpointRecord {
    /// Stable service-endpoint identifier.
    pub service_endpoint_id: String,
    /// Stable service-instance identifier owning this endpoint.
    pub service_instance_id: String,
    /// Stable cell identifier owning this endpoint.
    pub cell_id: String,
    /// Logical service-group identifier served by this endpoint.
    pub service_group: String,
    /// Stable participant registration currently backing the endpoint.
    pub participant_registration_id: String,
    /// Optional node name associated with the serving participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// Concrete service address published for this endpoint.
    pub address: String,
    /// Transport protocol used to reach this endpoint.
    pub protocol: ServiceEndpointProtocol,
    /// Optional readiness state currently advertised by the backing participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness: Option<LeaseReadiness>,
    /// Optional drain intent currently advertised by the backing participant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_intent: Option<LeaseDrainIntent>,
    /// Optional linked lease freshness when the participant published a lease-backed state snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_freshness: Option<LeaseFreshness>,
    /// Monotonic revision of the source projection that produced this record.
    #[serde(default)]
    pub revision: u64,
    /// Stable lease identifiers linked to this endpoint.
    #[serde(default)]
    pub linked_lease_ids: Vec<String>,
    /// Timestamp when this endpoint record was first published.
    pub registered_at: OffsetDateTime,
    /// Timestamp when this endpoint record was most recently updated.
    pub updated_at: OffsetDateTime,
}

impl ServiceEndpointRecord {
    /// Build one empty service-endpoint record.
    pub fn new(
        service_endpoint_id: impl Into<String>,
        service_instance_id: impl Into<String>,
        cell_id: impl Into<String>,
        service_group: impl Into<String>,
        participant_registration_id: impl Into<String>,
        address: impl Into<String>,
        protocol: ServiceEndpointProtocol,
        revision: u64,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            service_endpoint_id: trimmed_string(service_endpoint_id),
            service_instance_id: trimmed_string(service_instance_id),
            cell_id: trimmed_string(cell_id),
            service_group: trimmed_string(service_group),
            participant_registration_id: trimmed_string(participant_registration_id),
            node_name: None,
            address: trimmed_string(address),
            protocol,
            readiness: None,
            drain_intent: None,
            lease_freshness: None,
            revision,
            linked_lease_ids: Vec::new(),
            registered_at: now,
            updated_at: now,
        }
    }

    /// Project one concrete address publication from a first-class service instance record.
    pub fn from_service_instance(
        service_instance: &ServiceInstanceRecord,
        address: impl Into<String>,
        protocol: ServiceEndpointProtocol,
    ) -> Self {
        let address = trimmed_string(address);
        let mut record = Self::new(
            service_endpoint_record_id(
                service_instance.service_instance_id.clone(),
                protocol,
                address.clone(),
            ),
            service_instance.service_instance_id.clone(),
            service_instance.cell_id.clone(),
            service_instance.service_group.clone(),
            service_instance.participant_registration_id.clone(),
            address,
            protocol,
            service_instance.revision,
        )
        .with_linked_lease_ids(service_instance.linked_lease_ids.iter().cloned());
        record.node_name = service_instance
            .node_name
            .as_ref()
            .and_then(|value| trimmed_optional_string(value.clone()));
        record.readiness = service_instance.readiness;
        record.drain_intent = service_instance.drain_intent;
        record.lease_freshness = service_instance.lease_freshness;
        record.registered_at = service_instance.registered_at;
        record.updated_at = service_instance.updated_at;
        record
    }

    /// Replace the linked lease identifiers for this endpoint.
    pub fn with_linked_lease_ids<I, S>(mut self, linked_lease_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.linked_lease_ids = normalized_string_list(linked_lease_ids);
        self
    }
}

/// File-backed durable collection of service-endpoint records.
pub type ServiceEndpointCollection = DocumentStore<ServiceEndpointRecord>;

/// Stable cursor used to consume deterministic service-endpoint changes.
pub type ServiceEndpointCursor = DocumentCursor;

/// One deterministic service-endpoint mutation snapshot.
pub type ServiceEndpointChange = DocumentChange<ServiceEndpointRecord>;

/// One ordered page of deterministic service-endpoint changes.
pub type ServiceEndpointChangePage = DocumentChangePage<ServiceEndpointRecord>;

/// Concrete listener binding currently advertised for one participant-backed service group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEndpointBinding {
    service_group: String,
    address: String,
    protocol: ServiceEndpointProtocol,
}

impl ServiceEndpointBinding {
    /// Build one concrete service-endpoint binding.
    pub fn new(
        service_group: impl Into<String>,
        address: impl Into<String>,
        protocol: ServiceEndpointProtocol,
    ) -> Self {
        Self {
            service_group: trimmed_string(service_group),
            address: trimmed_string(address),
            protocol,
        }
    }

    /// Return the logical service group served by this binding.
    pub fn service_group(&self) -> &str {
        self.service_group.as_str()
    }

    /// Return the concrete listener address served by this binding.
    pub fn address(&self) -> &str {
        self.address.as_str()
    }

    /// Return the transport protocol used by this binding.
    pub const fn protocol(&self) -> ServiceEndpointProtocol {
        self.protocol
    }
}

/// Converge one durable cell-directory record against the freshest linked lease state.
pub fn converge_cell_directory_participants_at<'a, I>(
    cell_directory: &CellDirectoryRecord,
    lease_registrations: I,
    observed_at: OffsetDateTime,
) -> CellDirectoryRecord
where
    I: IntoIterator<Item = &'a LeaseRegistrationRecord>,
{
    let registrations_by_id = lease_registrations
        .into_iter()
        .map(|registration| (registration.registration_id.as_str(), registration))
        .collect::<BTreeMap<_, _>>();
    let mut participants = cell_directory
        .participants
        .iter()
        .map(|participant| {
            let registration_id = participant
                .lease_registration_id
                .as_deref()
                .unwrap_or(participant.registration_id.as_str());
            let linked_registration = registrations_by_id.get(registration_id).copied();
            converge_cell_participant_at(participant, linked_registration, observed_at)
        })
        .collect::<Vec<_>>();
    apply_takeover_acknowledgements(&mut participants, observed_at);
    if participants == cell_directory.participants {
        return cell_directory.clone();
    }

    let mut converged = cell_directory.clone();
    converged.participants = participants;
    converged.touch();
    converged
}

fn apply_takeover_acknowledgements(
    participants: &mut [CellParticipantRecord],
    observed_at: OffsetDateTime,
) {
    let replacement_candidates = participants
        .iter()
        .filter_map(|participant| {
            participant
                .state
                .as_ref()
                .is_some_and(healthy_cell_service_group_participant_state)
                .then_some((
                    participant.registration_id.clone(),
                    participant.service_groups.clone(),
                ))
        })
        .collect::<Vec<_>>();

    for participant in participants.iter_mut() {
        let Some(state) = participant.state.as_mut() else {
            continue;
        };
        if state.published_drain_intent() != LeaseDrainIntent::Draining {
            state.recompute_drain_phase();
            continue;
        }

        let next_takeover_registration_id = replacement_candidates
            .iter()
            .find(|(registration_id, service_groups)| {
                registration_id != participant.registration_id.as_str()
                    && shares_service_group(
                        participant.service_groups.as_slice(),
                        service_groups.as_slice(),
                    )
            })
            .map(|(registration_id, _)| registration_id.clone());
        let next_takeover_acknowledged_at =
            next_takeover_registration_id
                .as_ref()
                .map(|registration_id| {
                    if state.takeover_registration_id.as_deref() == Some(registration_id.as_str()) {
                        state.takeover_acknowledged_at.unwrap_or(observed_at)
                    } else {
                        observed_at
                    }
                });

        state.takeover_registration_id = next_takeover_registration_id;
        state.takeover_acknowledged_at = next_takeover_acknowledged_at;
        state.recompute_drain_phase();
    }
}

fn shares_service_group(left: &[String], right: &[String]) -> bool {
    left.iter()
        .any(|left_group| right.iter().any(|right_group| left_group == right_group))
}

fn runtime_participant_is_healthy(participant: &CellParticipantRecord) -> bool {
    participant.participant_kind == "runtime_process"
        && participant
            .state
            .as_ref()
            .is_some_and(healthy_cell_service_group_participant_state)
}

fn linked_registration_id_for_participant(participant: &CellParticipantRecord) -> String {
    participant
        .lease_registration_id
        .as_ref()
        .and_then(|registration_id| trimmed_optional_string(registration_id.clone()))
        .unwrap_or_else(|| trimmed_string(participant.registration_id.clone()))
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

fn trimmed_optional_str_matches(left: Option<&str>, right: Option<&str>) -> bool {
    match (
        left.map(str::trim).filter(|value| !value.is_empty()),
        right.map(str::trim).filter(|value| !value.is_empty()),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => true,
    }
}

fn runtime_registration_is_possible(registration: &LeaseRegistrationRecord) -> bool {
    if registration.subject_kind.trim() != "runtime_process" {
        return true;
    }

    let normalized_registration_id = trimmed_string(registration.registration_id.clone());
    let Some((expected_role, expected_node_name)) =
        runtime_process_identity_parts(normalized_registration_id.as_str())
    else {
        return false;
    };

    trimmed_string(registration.subject_id.clone()) == normalized_registration_id
        && trimmed_string(registration.role.clone()) == expected_role
        && trimmed_optional_str_matches(registration.node_name.as_deref(), Some(expected_node_name))
}

fn runtime_participant_is_possible(participant: &CellParticipantRecord) -> bool {
    if participant.participant_kind.trim() != "runtime_process" {
        return true;
    }

    let normalized_registration_id = trimmed_string(participant.registration_id.clone());
    let Some((expected_role, expected_node_name)) =
        runtime_process_identity_parts(normalized_registration_id.as_str())
    else {
        return false;
    };

    trimmed_string(participant.subject_id.clone()) == normalized_registration_id
        && trimmed_string(participant.role.clone()) == expected_role
        && trimmed_optional_str_matches(participant.node_name.as_deref(), Some(expected_node_name))
        && participant
            .lease_registration_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none_or(|lease_registration_id| lease_registration_id == normalized_registration_id)
}

fn runtime_participant_registration_link_is_possible(
    participant: &CellParticipantRecord,
    registration: &LeaseRegistrationRecord,
) -> bool {
    let participant_is_runtime = participant.participant_kind.trim() == "runtime_process";
    let registration_is_runtime = registration.subject_kind.trim() == "runtime_process";
    if !participant_is_runtime && !registration_is_runtime {
        return true;
    }
    if !participant_is_runtime || !registration_is_runtime {
        return false;
    }

    runtime_participant_is_possible(participant)
        && runtime_registration_is_possible(registration)
        && trimmed_string(participant.registration_id.clone())
            == trimmed_string(registration.registration_id.clone())
        && trimmed_string(participant.subject_id.clone())
            == trimmed_string(registration.subject_id.clone())
        && trimmed_string(participant.role.clone()) == trimmed_string(registration.role.clone())
        && trimmed_optional_str_matches(
            participant.node_name.as_deref(),
            registration.node_name.as_deref(),
        )
        && participant
            .lease_registration_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none_or(|lease_registration_id| {
                lease_registration_id == registration.registration_id.trim()
            })
}

fn quarantined_runtime_participant_registration_ids(
    participants: &[CellParticipantRecord],
    active_registrations: &BTreeMap<String, LeaseRegistrationRecord>,
) -> BTreeSet<String> {
    let mut quarantined_participant_registration_ids =
        conflicting_runtime_participant_registration_ids(participants);

    for participant in participants
        .iter()
        .filter(|participant| participant.participant_kind.trim() == "runtime_process")
    {
        if !runtime_participant_is_possible(participant) {
            quarantined_participant_registration_ids.insert(participant.registration_id.clone());
            continue;
        }

        let linked_registration_id = linked_registration_id_for_participant(participant);
        let Some(linked_registration) = active_registrations.get(linked_registration_id.as_str())
        else {
            continue;
        };
        if !runtime_participant_registration_link_is_possible(participant, linked_registration) {
            quarantined_participant_registration_ids.insert(participant.registration_id.clone());
        }
    }

    quarantined_participant_registration_ids
}

fn conflicting_runtime_participant_registration_ids(
    participants: &[CellParticipantRecord],
) -> BTreeSet<String> {
    let healthy_runtime_participants = participants
        .iter()
        .filter(|participant| runtime_participant_is_healthy(participant))
        .collect::<Vec<_>>();
    let mut conflicting_registration_ids = BTreeSet::new();

    let mut registration_ids_by_service_group = BTreeMap::<String, Vec<String>>::new();
    for participant in &healthy_runtime_participants {
        for service_group in &participant.service_groups {
            let service_group = trimmed_string(service_group.clone());
            if service_group.is_empty() {
                continue;
            }
            registration_ids_by_service_group
                .entry(service_group)
                .or_default()
                .push(participant.registration_id.clone());
        }
    }
    for registration_ids in registration_ids_by_service_group.into_values() {
        if registration_ids.len() > 1 {
            conflicting_registration_ids.extend(registration_ids);
        }
    }

    extend_conflicting_runtime_participant_ids_for_duplicate_value(
        &mut conflicting_registration_ids,
        &healthy_runtime_participants,
        |participant| Some(participant.subject_id.as_str()),
    );
    extend_conflicting_runtime_participant_ids_for_duplicate_value(
        &mut conflicting_registration_ids,
        &healthy_runtime_participants,
        |participant| participant.lease_registration_id.as_deref(),
    );

    conflicting_registration_ids
}

fn extend_conflicting_runtime_participant_ids_for_duplicate_value<F>(
    conflicting_registration_ids: &mut BTreeSet<String>,
    healthy_runtime_participants: &[&CellParticipantRecord],
    value_for: F,
) where
    F: Fn(&CellParticipantRecord) -> Option<&str>,
{
    let mut participant_registration_ids_by_value = BTreeMap::<String, Vec<String>>::new();

    for participant in healthy_runtime_participants {
        let Some(value) = value_for(participant)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        participant_registration_ids_by_value
            .entry(value.to_owned())
            .or_default()
            .push(participant.registration_id.clone());
    }

    for participant_registration_ids in participant_registration_ids_by_value.into_values() {
        if participant_registration_ids.len() > 1 {
            conflicting_registration_ids.extend(participant_registration_ids);
        }
    }
}

const LOCAL_CELL_REGISTRY_PAGE_LIMIT: usize = 128;
const LOCAL_CELL_REGISTRY_SNAPSHOT_LIMIT: usize = 4;

/// Cursor-keyed registry cache snapshot persisted for bounded warm starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalCellRegistryCacheSnapshot {
    /// Timestamp when the cache snapshot was captured.
    pub captured_at: OffsetDateTime,
    /// Lease cursor represented by this snapshot.
    #[serde(default)]
    pub lease_cursor: LeaseRegistrationCursor,
    /// Cell-directory cursor represented by this snapshot.
    #[serde(default)]
    pub cell_directory_cursor: CellDirectoryCursor,
    /// Active lease registrations materialized by this snapshot.
    #[serde(default)]
    pub active_registrations: BTreeMap<String, LeaseRegistrationRecord>,
    /// Lease registrations currently quarantined because the runtime participant slice conflicted.
    #[serde(default)]
    pub quarantined_registrations: BTreeMap<String, LeaseRegistrationRecord>,
}

/// Durable replay state used to warm one local cell-registry publication path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LocalCellRegistryState {
    /// Most recent lease-registration cursor consumed into the local registry cache.
    #[serde(default)]
    pub lease_cursor: LeaseRegistrationCursor,
    /// Most recent cell-directory cursor consumed to detect local directory drift.
    #[serde(default)]
    pub cell_directory_cursor: CellDirectoryCursor,
    /// Active lease registrations currently projected into the local cell directory.
    #[serde(default)]
    pub active_registrations: BTreeMap<String, LeaseRegistrationRecord>,
    /// Conflicting lease registrations withheld from active reconciliation until the conflict clears.
    #[serde(default)]
    pub quarantined_registrations: BTreeMap<String, LeaseRegistrationRecord>,
    /// Small cursor-keyed checkpoint ring used to rehydrate the active cache without replaying from origin.
    #[serde(default)]
    pub cache_snapshots: BTreeMap<String, LocalCellRegistryCacheSnapshot>,
}

impl LocalCellRegistryState {
    fn warm_active_registrations_from_snapshot(&mut self) {
        if !self.active_registrations.is_empty() || !self.quarantined_registrations.is_empty() {
            return;
        }

        let Some(snapshot) = self
            .cache_snapshots
            .values()
            .filter(|snapshot| {
                snapshot.lease_cursor.revision <= self.lease_cursor.revision
                    && snapshot.cell_directory_cursor.revision
                        <= self.cell_directory_cursor.revision
            })
            .max_by_key(|snapshot| {
                (
                    snapshot.lease_cursor.revision,
                    snapshot.cell_directory_cursor.revision,
                )
            })
            .cloned()
        else {
            return;
        };

        self.lease_cursor = snapshot.lease_cursor;
        self.cell_directory_cursor = snapshot.cell_directory_cursor;
        self.active_registrations = snapshot.active_registrations;
        self.quarantined_registrations = snapshot.quarantined_registrations;
    }

    fn restore_quarantined_registrations(&mut self) {
        if self.quarantined_registrations.is_empty() {
            return;
        }

        self.active_registrations
            .extend(std::mem::take(&mut self.quarantined_registrations));
    }

    fn quarantine_invalid_runtime_registrations(&mut self) {
        let invalid_registration_ids = self
            .active_registrations
            .iter()
            .filter_map(|(registration_id, registration)| {
                (!runtime_registration_is_possible(registration)).then_some(registration_id.clone())
            })
            .collect::<Vec<_>>();

        for registration_id in invalid_registration_ids {
            if let Some(registration) = self.active_registrations.remove(registration_id.as_str()) {
                self.quarantined_registrations
                    .insert(registration_id, registration);
            }
        }
    }

    fn quarantine_conflicting_runtime_registrations(
        &mut self,
        participants: &[CellParticipantRecord],
    ) -> BTreeSet<String> {
        let quarantined_participant_registration_ids =
            quarantined_runtime_participant_registration_ids(
                participants,
                &self.active_registrations,
            );
        for participant in participants.iter().filter(|participant| {
            quarantined_participant_registration_ids.contains(participant.registration_id.as_str())
        }) {
            let registration_id = linked_registration_id_for_participant(participant);
            if let Some(registration) = self.active_registrations.remove(registration_id.as_str()) {
                self.quarantined_registrations
                    .insert(registration_id, registration);
            }
        }
        quarantined_participant_registration_ids
    }

    fn persist_cache_snapshot(&mut self, captured_at: OffsetDateTime) {
        let snapshot = LocalCellRegistryCacheSnapshot {
            captured_at,
            lease_cursor: self.lease_cursor,
            cell_directory_cursor: self.cell_directory_cursor,
            active_registrations: self.active_registrations.clone(),
            quarantined_registrations: self.quarantined_registrations.clone(),
        };
        self.cache_snapshots.insert(
            local_cell_registry_cache_snapshot_key(
                snapshot.lease_cursor,
                snapshot.cell_directory_cursor,
            ),
            snapshot,
        );
        while self.cache_snapshots.len() > LOCAL_CELL_REGISTRY_SNAPSHOT_LIMIT {
            let Some(oldest_key) = self.cache_snapshots.keys().next().cloned() else {
                break;
            };
            self.cache_snapshots.remove(oldest_key.as_str());
        }
    }

    fn restore_active_registrations_from_checkpoint(
        &mut self,
        checkpoint: LeaseRegistrationSnapshotCheckpoint,
    ) {
        self.lease_cursor = checkpoint.cursor;
        self.active_registrations = checkpoint
            .records
            .into_iter()
            .filter_map(|(key, document)| (!document.deleted).then_some((key, document.value)))
            .collect();
        self.quarantined_registrations.clear();
    }

    fn restore_cell_directory_cursor_from_checkpoint(
        &mut self,
        checkpoint: CellDirectorySnapshotCheckpoint,
    ) {
        self.cell_directory_cursor = checkpoint.cursor;
    }
}

fn local_cell_registry_cache_snapshot_key(
    lease_cursor: LeaseRegistrationCursor,
    cell_directory_cursor: CellDirectoryCursor,
) -> String {
    format!(
        "lease-{:020}-directory-{:020}",
        lease_cursor.revision, cell_directory_cursor.revision
    )
}

/// Publication input for one local cell-registry update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCellRegistryPublication {
    owns_directory_reconciliation: bool,
    cell_id: String,
    cell_name: String,
    region: RegionDirectoryRecord,
    registration: LeaseRegistrationRecord,
    participant: CellParticipantRecord,
    service_endpoint_bindings: Vec<ServiceEndpointBinding>,
}

impl LocalCellRegistryPublication {
    /// Build one local cell-registry publication request.
    pub fn new(
        cell_id: impl Into<String>,
        cell_name: impl Into<String>,
        region: RegionDirectoryRecord,
        registration: LeaseRegistrationRecord,
        participant: CellParticipantRecord,
    ) -> Self {
        Self {
            owns_directory_reconciliation: false,
            cell_id: trimmed_string(cell_id),
            cell_name: trimmed_string(cell_name),
            region,
            registration,
            participant,
            service_endpoint_bindings: Vec::new(),
        }
    }

    /// Mark whether this caller owns full cell-directory reconciliation for the target cell.
    pub fn with_directory_reconciliation_ownership(
        mut self,
        owns_directory_reconciliation: bool,
    ) -> Self {
        self.owns_directory_reconciliation = owns_directory_reconciliation;
        self
    }

    /// Attach concrete service-endpoint bindings for the publishing participant.
    pub fn with_service_endpoint_bindings<I>(mut self, bindings: I) -> Self
    where
        I: IntoIterator<Item = ServiceEndpointBinding>,
    {
        self.service_endpoint_bindings.extend(bindings);
        self
    }

    fn cell_id(&self) -> &str {
        self.cell_id.as_str()
    }

    fn participant_registration_id(&self) -> &str {
        self.participant.registration_id.as_str()
    }

    fn service_endpoint_bindings(&self) -> &[ServiceEndpointBinding] {
        self.service_endpoint_bindings.as_slice()
    }

    fn seeded_cell_directory(&self) -> CellDirectoryRecord {
        CellDirectoryRecord::new(
            self.cell_id.clone(),
            self.cell_name.clone(),
            self.region.clone(),
        )
    }
}

/// Prepared local cell-registry mutation that callers may extend before commit.
#[derive(Debug, Clone)]
pub struct LocalCellRegistryDraft {
    cell_directory_key: String,
    cell_directory: CellDirectoryRecord,
    cell_directory_expected_version: Option<u64>,
    state: Option<LocalCellRegistryState>,
    state_expected_version: Option<u64>,
}

impl LocalCellRegistryDraft {
    /// Borrow the prepared cell-directory record.
    pub fn cell_directory(&self) -> &CellDirectoryRecord {
        &self.cell_directory
    }

    /// Mutate the prepared cell-directory record before commit.
    pub fn cell_directory_mut(&mut self) -> &mut CellDirectoryRecord {
        &mut self.cell_directory
    }
}

/// Shared boundary for publishing one process into the local cell directory.
#[derive(Debug, Clone)]
pub struct LocalCellRegistry {
    state_store: MetadataCollection<LocalCellRegistryState>,
}

impl LocalCellRegistry {
    /// Wrap one durable state store behind the shared local registry boundary.
    pub fn new(state_store: MetadataCollection<LocalCellRegistryState>) -> Self {
        Self { state_store }
    }

    /// Open the default file-backed local registry state store for all-in-one mode.
    pub async fn open_local(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::new(MetadataCollection::open_local(path).await?))
    }

    /// Prepare one local cell-directory publication and return a mutable draft for caller-specific mutations.
    pub async fn prepare_publication(
        &self,
        cell_directory_store: &CellDirectoryCollection,
        registration_store: &LeaseRegistrationCollection,
        publication: &LocalCellRegistryPublication,
        observed_at: OffsetDateTime,
    ) -> Result<LocalCellRegistryDraft> {
        let mut state = None;
        let mut state_expected_version = None;
        let existing = cell_directory_store.get(publication.cell_id()).await?;

        if publication.owns_directory_reconciliation {
            let stored_state: Option<StoredDocument<LocalCellRegistryState>> =
                self.state_store.get(publication.cell_id()).await?;
            state_expected_version = stored_state.as_ref().map(|stored| stored.version);
            let mut next_state = stored_state
                .and_then(|stored| (!stored.deleted).then_some(stored.value))
                .unwrap_or_default();
            next_state.warm_active_registrations_from_snapshot();
            next_state.restore_quarantined_registrations();
            self.advance_cell_directory_cursor(cell_directory_store, &mut next_state)
                .await?;
            self.replay_lease_changes(registration_store, &mut next_state)
                .await?;
            next_state.active_registrations.insert(
                publication.registration.registration_id.clone(),
                publication.registration.clone(),
            );
            next_state.quarantine_invalid_runtime_registrations();
            state = Some(next_state);
        }

        let cell_directory_expected_version = existing.as_ref().map(|stored| stored.version);
        let mut record = existing
            .and_then(|stored| (!stored.deleted).then_some(stored.value))
            .unwrap_or_else(|| publication.seeded_cell_directory());
        let previous_participant = record
            .participants
            .iter()
            .find(|participant| {
                participant.registration_id == publication.participant.registration_id
            })
            .cloned();
        record.set_region(publication.region.clone());
        record.set_cell_name(publication.cell_name.clone());
        if let Some(state) = state.as_ref() {
            record = converge_cell_directory_from_registry_cache(
                &record,
                &state.active_registrations,
                observed_at,
            );
        }
        record.upsert_participant(publication.participant.clone());
        if let Some(previous_state) = previous_participant
            .as_ref()
            .and_then(|participant| participant.state.as_ref())
            && let Some(current_state) = record
                .participants
                .iter_mut()
                .find(|participant| {
                    participant.registration_id == publication.participant.registration_id
                })
                .and_then(|participant| participant.state.as_mut())
        {
            *current_state =
                carry_forward_takeover_acknowledgement(Some(previous_state), current_state.clone());
        }
        if let Some(state) = state.as_mut() {
            let _ =
                state.quarantine_conflicting_runtime_registrations(record.participants.as_slice());
            state.persist_cache_snapshot(observed_at);
        }
        apply_takeover_acknowledgements(&mut record.participants, observed_at);

        Ok(LocalCellRegistryDraft {
            cell_directory_key: publication.cell_id.clone(),
            cell_directory: record,
            cell_directory_expected_version,
            state,
            state_expected_version,
        })
    }

    /// Commit a prepared local cell-directory publication and persist any replay state updates.
    pub async fn commit(
        &self,
        cell_directory_store: &CellDirectoryCollection,
        draft: LocalCellRegistryDraft,
    ) -> Result<StoredDocument<CellDirectoryRecord>> {
        let stored_record = cell_directory_store
            .upsert(
                draft.cell_directory_key.as_str(),
                draft.cell_directory,
                draft.cell_directory_expected_version,
            )
            .await?;
        if let Some(state) = draft.state {
            self.state_store
                .upsert(
                    draft.cell_directory_key.as_str(),
                    state,
                    draft.state_expected_version,
                )
                .await?;
        }
        Ok(stored_record)
    }

    /// Prepare and commit one local cell-directory publication in a single step.
    pub async fn publish(
        &self,
        cell_directory_store: &CellDirectoryCollection,
        registration_store: &LeaseRegistrationCollection,
        publication: &LocalCellRegistryPublication,
        observed_at: OffsetDateTime,
    ) -> Result<CellDirectoryRecord> {
        let draft = self
            .prepare_publication(
                cell_directory_store,
                registration_store,
                publication,
                observed_at,
            )
            .await?;
        Ok(self.commit(cell_directory_store, draft).await?.value)
    }

    /// Prepare and commit one local cell-directory publication while synchronizing
    /// first-class service-instance records for the whole cell and concrete
    /// service-endpoint records for the publishing participant.
    pub async fn publish_with_service_records(
        &self,
        cell_directory_store: &CellDirectoryCollection,
        registration_store: &LeaseRegistrationCollection,
        service_instance_store: &ServiceInstanceCollection,
        service_endpoint_store: &ServiceEndpointCollection,
        publication: &LocalCellRegistryPublication,
        observed_at: OffsetDateTime,
    ) -> Result<CellDirectoryRecord> {
        let draft = self
            .prepare_publication(
                cell_directory_store,
                registration_store,
                publication,
                observed_at,
            )
            .await?;
        let participant_service_instances =
            resolve_cell_service_instances(draft.cell_directory(), 0)
                .into_iter()
                .filter(|instance| {
                    instance.participant_registration_id
                        == publication.participant_registration_id()
                })
                .collect::<Vec<_>>();
        let _ = resolve_service_endpoint_records(
            participant_service_instances.as_slice(),
            publication.service_endpoint_bindings(),
        )?;

        let stored_record = self.commit(cell_directory_store, draft).await?;
        let revision = stored_record.version;
        let cell_directory = stored_record.value;
        let cell_id = cell_directory.cell_id.clone();
        let participant_registration_id = publication.participant_registration_id().to_owned();

        let service_instances = resolve_cell_service_instances(&cell_directory, revision);
        sync_service_instance_store_for_cell(
            service_instance_store,
            cell_id.as_str(),
            service_instances.as_slice(),
        )
        .await?;

        let participant_service_instances = service_instances
            .into_iter()
            .filter(|instance| instance.participant_registration_id == participant_registration_id)
            .collect::<Vec<_>>();
        let service_endpoints = resolve_service_endpoint_records(
            participant_service_instances.as_slice(),
            publication.service_endpoint_bindings(),
        )?;
        sync_service_endpoint_store_for_participant(
            service_endpoint_store,
            cell_id.as_str(),
            publication.participant_registration_id(),
            service_endpoints.as_slice(),
        )
        .await?;

        Ok(cell_directory)
    }

    async fn advance_cell_directory_cursor(
        &self,
        cell_directory_store: &CellDirectoryCollection,
        state: &mut LocalCellRegistryState,
    ) -> Result<()> {
        replay_document_change_feed(
            state,
            state.cell_directory_cursor,
            |cursor| cell_directory_store.changes_since(cursor, LOCAL_CELL_REGISTRY_PAGE_LIMIT),
            || cell_directory_store.snapshot_checkpoint(),
            |state, cursor| state.cell_directory_cursor = cursor,
            |_state, _changes| Ok(()),
            |state, checkpoint| {
                state.restore_cell_directory_cursor_from_checkpoint(checkpoint);
                Ok(())
            },
        )
        .await
    }

    async fn replay_lease_changes(
        &self,
        registration_store: &LeaseRegistrationCollection,
        state: &mut LocalCellRegistryState,
    ) -> Result<()> {
        replay_document_change_feed(
            state,
            state.lease_cursor,
            |cursor| registration_store.changes_since(cursor, LOCAL_CELL_REGISTRY_PAGE_LIMIT),
            || registration_store.snapshot_checkpoint(),
            |state, cursor| state.lease_cursor = cursor,
            |state, changes| {
                for change in changes {
                    if change.document.deleted {
                        state.active_registrations.remove(change.key.as_str());
                    } else {
                        state
                            .active_registrations
                            .insert(change.key, change.document.value);
                    }
                }
                Ok(())
            },
            |state, checkpoint| {
                state.restore_active_registrations_from_checkpoint(checkpoint);
                Ok(())
            },
        )
        .await
    }
}

fn resolve_service_endpoint_records(
    service_instances: &[ServiceInstanceRecord],
    bindings: &[ServiceEndpointBinding],
) -> Result<Vec<ServiceEndpointRecord>> {
    let instances_by_group = service_instances
        .iter()
        .map(|instance| (instance.service_group.as_str(), instance))
        .collect::<BTreeMap<_, _>>();
    let mut endpoints = BTreeMap::<String, ServiceEndpointRecord>::new();

    for binding in bindings {
        if binding.service_group().is_empty() {
            return Err(PlatformError::invalid(
                "service endpoint bindings require a non-empty service_group",
            ));
        }
        if binding.address().is_empty() {
            return Err(PlatformError::invalid(format!(
                "service endpoint binding for service_group `{}` requires a non-empty address",
                binding.service_group()
            )));
        }

        let Some(service_instance) = instances_by_group.get(binding.service_group()).copied()
        else {
            return Err(PlatformError::invalid(format!(
                "service endpoint binding for service_group `{}` does not match any projected service instance",
                binding.service_group()
            )));
        };

        let endpoint = ServiceEndpointRecord::from_service_instance(
            service_instance,
            binding.address(),
            binding.protocol(),
        );
        endpoints.insert(endpoint.service_endpoint_id.clone(), endpoint);
    }

    Ok(endpoints.into_values().collect())
}

async fn sync_service_instance_store_for_cell(
    service_instance_store: &ServiceInstanceCollection,
    cell_id: &str,
    projections: &[ServiceInstanceRecord],
) -> Result<()> {
    let mut existing = service_instance_store
        .list()
        .await?
        .into_iter()
        .filter(|(_, stored)| stored.value.cell_id == cell_id)
        .collect::<BTreeMap<_, _>>();

    for projection in projections {
        match existing.remove(projection.service_instance_id.as_str()) {
            Some(stored) if !stored.deleted && stored.value == *projection => {}
            Some(stored) => {
                service_instance_store
                    .upsert(
                        projection.service_instance_id.as_str(),
                        projection.clone(),
                        Some(stored.version),
                    )
                    .await?;
            }
            None => {
                service_instance_store
                    .create(projection.service_instance_id.as_str(), projection.clone())
                    .await?;
            }
        }
    }

    for (service_instance_id, stored) in existing {
        if !stored.deleted {
            service_instance_store
                .soft_delete(service_instance_id.as_str(), Some(stored.version))
                .await?;
        }
    }

    Ok(())
}

async fn sync_service_endpoint_store_for_participant(
    service_endpoint_store: &ServiceEndpointCollection,
    cell_id: &str,
    participant_registration_id: &str,
    projections: &[ServiceEndpointRecord],
) -> Result<()> {
    let mut existing = service_endpoint_store
        .list()
        .await?
        .into_iter()
        .filter(|(_, stored)| {
            stored.value.cell_id == cell_id
                && stored.value.participant_registration_id == participant_registration_id
        })
        .collect::<BTreeMap<_, _>>();

    for projection in projections {
        match existing.remove(projection.service_endpoint_id.as_str()) {
            Some(stored) if !stored.deleted && stored.value == *projection => {}
            Some(stored) => {
                service_endpoint_store
                    .upsert(
                        projection.service_endpoint_id.as_str(),
                        projection.clone(),
                        Some(stored.version),
                    )
                    .await?;
            }
            None => {
                service_endpoint_store
                    .create(projection.service_endpoint_id.as_str(), projection.clone())
                    .await?;
            }
        }
    }

    for (service_endpoint_id, stored) in existing {
        if !stored.deleted {
            service_endpoint_store
                .soft_delete(service_endpoint_id.as_str(), Some(stored.version))
                .await?;
        }
    }

    Ok(())
}

/// Converge one cell-directory record using the current local registry cache.
pub fn converge_cell_directory_from_registry_cache(
    cell_directory: &CellDirectoryRecord,
    active_registrations: &BTreeMap<String, LeaseRegistrationRecord>,
    observed_at: OffsetDateTime,
) -> CellDirectoryRecord {
    let linked_registrations = cell_directory
        .participants
        .iter()
        .filter_map(|participant| {
            let registration_id = participant
                .lease_registration_id
                .as_deref()
                .unwrap_or(participant.registration_id.as_str());
            active_registrations.get(registration_id)
        });
    converge_cell_directory_participants_at(cell_directory, linked_registrations, observed_at)
}

fn document_change_feed_was_compacted(error: &PlatformError) -> bool {
    error.code == ErrorCode::Conflict && error.message.contains("has been compacted")
}

/// One registry/discovery replay step from a durable document change feed.
enum ChangeFeedPageOrCheckpoint<Page, Checkpoint> {
    /// Another ordered page of source changes is available.
    Page(Page),
    /// Source history was compacted, so the caller must reseed from a snapshot checkpoint.
    Checkpoint(Checkpoint),
}

async fn load_change_feed_page_or_checkpoint<
    Page,
    Checkpoint,
    LoadPage,
    LoadPageFuture,
    LoadCheckpoint,
    LoadCheckpointFuture,
>(
    load_page: LoadPage,
    load_checkpoint: LoadCheckpoint,
) -> Result<ChangeFeedPageOrCheckpoint<Page, Checkpoint>>
where
    LoadPage: FnOnce() -> LoadPageFuture,
    LoadPageFuture: Future<Output = Result<Page>>,
    LoadCheckpoint: FnOnce() -> LoadCheckpointFuture,
    LoadCheckpointFuture: Future<Output = Result<Checkpoint>>,
{
    match load_page().await {
        Ok(page) => Ok(ChangeFeedPageOrCheckpoint::Page(page)),
        Err(error) if document_change_feed_was_compacted(&error) => Ok(
            ChangeFeedPageOrCheckpoint::Checkpoint(load_checkpoint().await?),
        ),
        Err(error) => Err(error),
    }
}

/// Replay one durable document-backed change feed until the caller is caught up,
/// reseeding from a snapshot checkpoint when the requested cursor has already
/// been compacted away.
async fn replay_document_change_feed<
    State,
    Record,
    LoadPage,
    LoadPageFuture,
    LoadCheckpoint,
    LoadCheckpointFuture,
    UpdateCursor,
    ApplyChanges,
    ApplyCheckpoint,
>(
    state: &mut State,
    initial_cursor: DocumentCursor,
    mut load_page: LoadPage,
    mut load_checkpoint: LoadCheckpoint,
    mut update_cursor: UpdateCursor,
    mut apply_changes: ApplyChanges,
    mut apply_checkpoint: ApplyCheckpoint,
) -> Result<()>
where
    LoadPage: FnMut(Option<DocumentCursor>) -> LoadPageFuture,
    LoadPageFuture: Future<Output = Result<DocumentChangePage<Record>>>,
    LoadCheckpoint: FnMut() -> LoadCheckpointFuture,
    LoadCheckpointFuture: Future<Output = Result<DocumentSnapshotCheckpoint<Record>>>,
    UpdateCursor: FnMut(&mut State, DocumentCursor),
    ApplyChanges: FnMut(&mut State, Vec<DocumentChange<Record>>) -> Result<()>,
    ApplyCheckpoint: FnMut(&mut State, DocumentSnapshotCheckpoint<Record>) -> Result<()>,
{
    let mut cursor = Some(initial_cursor);
    loop {
        match load_change_feed_page_or_checkpoint(|| load_page(cursor), &mut load_checkpoint)
            .await?
        {
            ChangeFeedPageOrCheckpoint::Page(page) => {
                let next_cursor = page.next_cursor;
                update_cursor(state, next_cursor);
                if page.changes.is_empty() {
                    return Ok(());
                }
                apply_changes(state, page.changes)?;
                cursor = Some(next_cursor);
            }
            ChangeFeedPageOrCheckpoint::Checkpoint(checkpoint) => {
                let checkpoint_cursor = checkpoint.cursor;
                apply_checkpoint(state, checkpoint)?;
                update_cursor(state, checkpoint_cursor);
                return Ok(());
            }
        }
    }
}

/// Shared trait for durable cell-directory records.
pub trait CellDirectoryStore: Send + Sync + 'static {
    /// List all cell directory records, including soft-deleted entries.
    fn list(
        &self,
    ) -> CellDirectoryResultFuture<'_, Vec<(String, StoredDocument<CellDirectoryRecord>)>>;

    /// Fetch one cell directory record by key.
    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> CellDirectoryResultFuture<'a, Option<StoredDocument<CellDirectoryRecord>>>;

    /// Return the current change-feed cursor for cell-directory records.
    fn current_cursor(&self) -> CellDirectoryResultFuture<'_, CellDirectoryCursor>;

    /// Return one ordered page of cell-directory changes after the supplied cursor.
    fn changes_since(
        &self,
        cursor: Option<CellDirectoryCursor>,
        limit: usize,
    ) -> CellDirectoryResultFuture<'_, CellDirectoryChangePage>;

    /// Create a new cell directory record. Fails when the key already exists.
    fn create<'a>(
        &'a self,
        key: &'a str,
        value: CellDirectoryRecord,
    ) -> CellDirectoryResultFuture<'a, StoredDocument<CellDirectoryRecord>>;

    /// Create or update a cell directory record with optimistic concurrency semantics.
    fn upsert<'a>(
        &'a self,
        key: &'a str,
        value: CellDirectoryRecord,
        expected_version: Option<u64>,
    ) -> CellDirectoryResultFuture<'a, StoredDocument<CellDirectoryRecord>>;

    /// Soft-delete a cell directory record with optional optimistic concurrency checking.
    fn soft_delete<'a>(
        &'a self,
        key: &'a str,
        expected_version: Option<u64>,
    ) -> CellDirectoryResultFuture<'a, ()>;
}

impl CellDirectoryStore for DocumentStore<CellDirectoryRecord>
where
    CellDirectoryRecord: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
{
    fn list(
        &self,
    ) -> CellDirectoryResultFuture<'_, Vec<(String, StoredDocument<CellDirectoryRecord>)>> {
        Box::pin(async move { DocumentStore::list(self).await })
    }

    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> CellDirectoryResultFuture<'a, Option<StoredDocument<CellDirectoryRecord>>> {
        Box::pin(async move { DocumentStore::get(self, key).await })
    }

    fn current_cursor(&self) -> CellDirectoryResultFuture<'_, CellDirectoryCursor> {
        Box::pin(async move { DocumentStore::current_cursor(self).await })
    }

    fn changes_since(
        &self,
        cursor: Option<CellDirectoryCursor>,
        limit: usize,
    ) -> CellDirectoryResultFuture<'_, CellDirectoryChangePage> {
        Box::pin(async move { DocumentStore::changes_since(self, cursor, limit).await })
    }

    fn create<'a>(
        &'a self,
        key: &'a str,
        value: CellDirectoryRecord,
    ) -> CellDirectoryResultFuture<'a, StoredDocument<CellDirectoryRecord>> {
        Box::pin(async move { DocumentStore::create(self, key, value).await })
    }

    fn upsert<'a>(
        &'a self,
        key: &'a str,
        value: CellDirectoryRecord,
        expected_version: Option<u64>,
    ) -> CellDirectoryResultFuture<'a, StoredDocument<CellDirectoryRecord>> {
        Box::pin(async move { DocumentStore::upsert(self, key, value, expected_version).await })
    }

    fn soft_delete<'a>(
        &'a self,
        key: &'a str,
        expected_version: Option<u64>,
    ) -> CellDirectoryResultFuture<'a, ()> {
        Box::pin(async move { DocumentStore::soft_delete(self, key, expected_version).await })
    }
}

/// Cloneable handle to a cell-directory backend.
#[derive(Clone)]
pub struct CellDirectoryCollection {
    inner: Arc<dyn CellDirectoryStore>,
    local_store: Option<DocumentStore<CellDirectoryRecord>>,
}

impl CellDirectoryCollection {
    /// Wrap a cell-directory backend behind the shared boundary.
    pub fn from_backend(backend: impl CellDirectoryStore) -> Self {
        Self {
            inner: Arc::new(backend),
            local_store: None,
        }
    }

    /// Wrap one local file-backed document store behind the shared boundary.
    pub fn from_local_store(store: DocumentStore<CellDirectoryRecord>) -> Self {
        Self {
            inner: Arc::new(store.clone()),
            local_store: Some(store),
        }
    }

    /// List all cell directory records, including soft-deleted entries.
    pub async fn list(&self) -> Result<Vec<(String, StoredDocument<CellDirectoryRecord>)>> {
        self.inner.list().await
    }

    /// Fetch one cell directory record by key.
    pub async fn get(&self, key: &str) -> Result<Option<StoredDocument<CellDirectoryRecord>>> {
        self.inner.get(key).await
    }

    /// Return the current change-feed cursor for cell-directory records.
    pub async fn current_cursor(&self) -> Result<CellDirectoryCursor> {
        self.inner.current_cursor().await
    }

    /// Return one ordered page of cell-directory changes after the supplied cursor.
    pub async fn changes_since(
        &self,
        cursor: Option<CellDirectoryCursor>,
        limit: usize,
    ) -> Result<CellDirectoryChangePage> {
        self.inner.changes_since(cursor, limit).await
    }

    /// Create a new cell directory record. Fails when the key already exists.
    pub async fn create(
        &self,
        key: &str,
        value: CellDirectoryRecord,
    ) -> Result<StoredDocument<CellDirectoryRecord>> {
        self.inner.create(key, value).await
    }

    /// Create or update a cell directory record with optimistic concurrency semantics.
    pub async fn upsert(
        &self,
        key: &str,
        value: CellDirectoryRecord,
        expected_version: Option<u64>,
    ) -> Result<StoredDocument<CellDirectoryRecord>> {
        self.inner.upsert(key, value, expected_version).await
    }

    /// Soft-delete a cell directory record with optional optimistic concurrency checking.
    pub async fn soft_delete(&self, key: &str, expected_version: Option<u64>) -> Result<()> {
        self.inner.soft_delete(key, expected_version).await
    }

    /// Return one full snapshot checkpoint at the current collection revision.
    pub async fn snapshot_checkpoint(&self) -> Result<CellDirectorySnapshotCheckpoint> {
        let Some(store) = &self.local_store else {
            return Err(PlatformError::unavailable(
                "cell-directory snapshot checkpoints are not supported by this backend",
            ));
        };
        store.snapshot_checkpoint().await
    }

    /// Open the default file-backed cell-directory backend for all-in-one mode.
    pub async fn open_local(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::from_local_store(
            DocumentStore::<CellDirectoryRecord>::open(path).await?,
        ))
    }
}

impl fmt::Debug for CellDirectoryCollection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let backend = if self.local_store.is_some() {
            "local_document_store"
        } else {
            "dyn CellDirectoryStore"
        };
        formatter
            .debug_struct("CellDirectoryCollection")
            .field("backend", &backend)
            .field("local_store", &self.local_store.is_some())
            .finish()
    }
}

/// Boxed future returned by cell-scoped service-group directory backends.
pub type CellServiceGroupDirectoryResultFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Stable cursor used to consume deterministic service-group directory changes.
pub type CellServiceGroupDirectoryCursor = DocumentCursor;

/// One deterministic service-group directory mutation snapshot.
pub type CellServiceGroupDirectoryChange = DocumentChange<CellServiceGroupDirectoryRecord>;

/// One ordered page of deterministic service-group directory changes.
pub type CellServiceGroupDirectoryChangePage = DocumentChangePage<CellServiceGroupDirectoryRecord>;

/// Point-in-time checkpoint used to reseed service-group directory consumers
/// after change-feed compaction.
pub type CellServiceGroupDirectorySnapshotCheckpoint =
    DocumentSnapshotCheckpoint<CellServiceGroupDirectoryRecord>;

/// Shared trait for durable cell-scoped service-group directory records.
pub trait CellServiceGroupDirectoryStore: Send + Sync + 'static {
    /// List all service-group directory records, including soft-deleted entries.
    fn list(
        &self,
    ) -> CellServiceGroupDirectoryResultFuture<
        '_,
        Vec<(String, StoredDocument<CellServiceGroupDirectoryRecord>)>,
    >;

    /// Fetch one service-group directory record by key.
    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> CellServiceGroupDirectoryResultFuture<
        'a,
        Option<StoredDocument<CellServiceGroupDirectoryRecord>>,
    >;

    /// Return the current change-feed cursor for service-group directory records.
    fn current_cursor(
        &self,
    ) -> CellServiceGroupDirectoryResultFuture<'_, CellServiceGroupDirectoryCursor>;

    /// Return one ordered page of service-group directory changes after the supplied cursor.
    fn changes_since(
        &self,
        cursor: Option<CellServiceGroupDirectoryCursor>,
        limit: usize,
    ) -> CellServiceGroupDirectoryResultFuture<'_, CellServiceGroupDirectoryChangePage>;

    /// Create a new service-group directory record. Fails when the key already exists.
    fn create<'a>(
        &'a self,
        key: &'a str,
        value: CellServiceGroupDirectoryRecord,
    ) -> CellServiceGroupDirectoryResultFuture<'a, StoredDocument<CellServiceGroupDirectoryRecord>>;

    /// Create or update a service-group directory record with optimistic concurrency semantics.
    fn upsert<'a>(
        &'a self,
        key: &'a str,
        value: CellServiceGroupDirectoryRecord,
        expected_version: Option<u64>,
    ) -> CellServiceGroupDirectoryResultFuture<'a, StoredDocument<CellServiceGroupDirectoryRecord>>;

    /// Soft-delete a service-group directory record with optional optimistic concurrency checking.
    fn soft_delete<'a>(
        &'a self,
        key: &'a str,
        expected_version: Option<u64>,
    ) -> CellServiceGroupDirectoryResultFuture<'a, ()>;
}

impl CellServiceGroupDirectoryStore for DocumentStore<CellServiceGroupDirectoryRecord>
where
    CellServiceGroupDirectoryRecord: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
{
    fn list(
        &self,
    ) -> CellServiceGroupDirectoryResultFuture<
        '_,
        Vec<(String, StoredDocument<CellServiceGroupDirectoryRecord>)>,
    > {
        Box::pin(async move { DocumentStore::list(self).await })
    }

    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> CellServiceGroupDirectoryResultFuture<
        'a,
        Option<StoredDocument<CellServiceGroupDirectoryRecord>>,
    > {
        Box::pin(async move { DocumentStore::get(self, key).await })
    }

    fn current_cursor(
        &self,
    ) -> CellServiceGroupDirectoryResultFuture<'_, CellServiceGroupDirectoryCursor> {
        Box::pin(async move { DocumentStore::current_cursor(self).await })
    }

    fn changes_since(
        &self,
        cursor: Option<CellServiceGroupDirectoryCursor>,
        limit: usize,
    ) -> CellServiceGroupDirectoryResultFuture<'_, CellServiceGroupDirectoryChangePage> {
        Box::pin(async move { DocumentStore::changes_since(self, cursor, limit).await })
    }

    fn create<'a>(
        &'a self,
        key: &'a str,
        value: CellServiceGroupDirectoryRecord,
    ) -> CellServiceGroupDirectoryResultFuture<'a, StoredDocument<CellServiceGroupDirectoryRecord>>
    {
        Box::pin(async move { DocumentStore::create(self, key, value).await })
    }

    fn upsert<'a>(
        &'a self,
        key: &'a str,
        value: CellServiceGroupDirectoryRecord,
        expected_version: Option<u64>,
    ) -> CellServiceGroupDirectoryResultFuture<'a, StoredDocument<CellServiceGroupDirectoryRecord>>
    {
        Box::pin(async move { DocumentStore::upsert(self, key, value, expected_version).await })
    }

    fn soft_delete<'a>(
        &'a self,
        key: &'a str,
        expected_version: Option<u64>,
    ) -> CellServiceGroupDirectoryResultFuture<'a, ()> {
        Box::pin(async move { DocumentStore::soft_delete(self, key, expected_version).await })
    }
}

/// Cloneable handle to a cell-scoped service-group directory backend.
#[derive(Clone)]
pub struct CellServiceGroupDirectoryCollection {
    inner: Arc<dyn CellServiceGroupDirectoryStore>,
    local_store: Option<DocumentStore<CellServiceGroupDirectoryRecord>>,
}

impl CellServiceGroupDirectoryCollection {
    /// Wrap a cell-scoped service-group directory backend behind the shared boundary.
    pub fn from_backend(backend: impl CellServiceGroupDirectoryStore) -> Self {
        Self {
            inner: Arc::new(backend),
            local_store: None,
        }
    }

    /// Wrap one local file-backed document store behind the shared boundary.
    pub fn from_local_store(store: DocumentStore<CellServiceGroupDirectoryRecord>) -> Self {
        Self {
            inner: Arc::new(store.clone()),
            local_store: Some(store),
        }
    }

    /// List all service-group directory records, including soft-deleted entries.
    pub async fn list(
        &self,
    ) -> Result<Vec<(String, StoredDocument<CellServiceGroupDirectoryRecord>)>> {
        self.inner.list().await
    }

    /// Fetch one service-group directory record by key.
    pub async fn get(
        &self,
        key: &str,
    ) -> Result<Option<StoredDocument<CellServiceGroupDirectoryRecord>>> {
        self.inner.get(key).await
    }

    /// Return the current change-feed cursor for service-group directory records.
    pub async fn current_cursor(&self) -> Result<CellServiceGroupDirectoryCursor> {
        self.inner.current_cursor().await
    }

    /// Return one ordered page of service-group directory changes after the supplied cursor.
    pub async fn changes_since(
        &self,
        cursor: Option<CellServiceGroupDirectoryCursor>,
        limit: usize,
    ) -> Result<CellServiceGroupDirectoryChangePage> {
        self.inner.changes_since(cursor, limit).await
    }

    /// Create a new service-group directory record. Fails when the key already exists.
    pub async fn create(
        &self,
        key: &str,
        value: CellServiceGroupDirectoryRecord,
    ) -> Result<StoredDocument<CellServiceGroupDirectoryRecord>> {
        self.inner.create(key, value).await
    }

    /// Create or update a service-group directory record with optimistic concurrency semantics.
    pub async fn upsert(
        &self,
        key: &str,
        value: CellServiceGroupDirectoryRecord,
        expected_version: Option<u64>,
    ) -> Result<StoredDocument<CellServiceGroupDirectoryRecord>> {
        self.inner.upsert(key, value, expected_version).await
    }

    /// Soft-delete a service-group directory record with optional optimistic concurrency checking.
    pub async fn soft_delete(&self, key: &str, expected_version: Option<u64>) -> Result<()> {
        self.inner.soft_delete(key, expected_version).await
    }

    /// Return one full snapshot checkpoint at the current collection revision.
    pub async fn snapshot_checkpoint(&self) -> Result<CellServiceGroupDirectorySnapshotCheckpoint> {
        let Some(store) = &self.local_store else {
            return Err(PlatformError::unavailable(
                "service-group directory snapshot checkpoints are not supported by this backend",
            ));
        };
        store.snapshot_checkpoint().await
    }

    /// Open the default file-backed service-group directory backend for all-in-one mode.
    pub async fn open_local(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::from_local_store(
            DocumentStore::<CellServiceGroupDirectoryRecord>::open(path).await?,
        ))
    }
}

impl fmt::Debug for CellServiceGroupDirectoryCollection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let backend = if self.local_store.is_some() {
            "local_document_store"
        } else {
            "dyn CellServiceGroupDirectoryStore"
        };
        formatter
            .debug_struct("CellServiceGroupDirectoryCollection")
            .field("backend", &backend)
            .field("local_store", &self.local_store.is_some())
            .finish()
    }
}

/// File-backed cache of cross-cell and cross-region service-group discovery projections.
pub type ServiceGroupDiscoveryCollection = DocumentStore<ServiceGroupDiscoveryRecord>;

const SERVICE_GROUP_DISCOVERY_PAGE_LIMIT: usize = 128;
const SERVICE_GROUP_DISCOVERY_STATE_KEY: &str = "service_group_discovery";

/// One cell slice attached to a cross-cell service-group discovery projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceGroupDiscoveryCellProjection {
    /// Stable cell identifier.
    pub cell_id: String,
    /// Human-meaningful cell name used by operators and reports.
    pub cell_name: String,
    /// Healthy participant registrations currently resolved for this logical group in the cell.
    #[serde(default)]
    pub resolved_registration_ids: Vec<String>,
    /// Conflict state derived from the cell-scoped healthy registrations.
    #[serde(default)]
    pub conflict_state: CellServiceGroupConflictState,
    /// All participant registrations currently advertising this logical group in the cell.
    #[serde(default)]
    pub registrations: Vec<CellServiceGroupRegistrationResolution>,
    /// Timestamp when this cell-scoped directory was first published.
    pub registered_at: OffsetDateTime,
    /// Timestamp when this cell-scoped directory was most recently updated.
    pub updated_at: OffsetDateTime,
}

impl ServiceGroupDiscoveryCellProjection {
    fn from_cell_directory_entry(
        cell_directory: &CellServiceGroupDirectoryRecord,
        entry: &CellServiceGroupDirectoryEntry,
    ) -> Self {
        Self {
            cell_id: trimmed_string(cell_directory.cell_id.clone()),
            cell_name: trimmed_string(cell_directory.cell_name.clone()),
            resolved_registration_ids: normalized_string_list(
                entry.resolved_registration_ids.iter().cloned(),
            ),
            conflict_state: entry.conflict_state,
            registrations: entry.registrations.clone(),
            registered_at: cell_directory.registered_at,
            updated_at: cell_directory.updated_at,
        }
    }
}

/// One region slice attached to a cross-cell service-group discovery projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceGroupDiscoveryRegionProjection {
    /// Stable region identifier.
    pub region_id: String,
    /// Human-meaningful region name used by operators and reports.
    pub region_name: String,
    /// Healthy cells currently resolving this logical group inside the region.
    #[serde(default)]
    pub healthy_cells: Vec<String>,
    /// Cell-level discovery slices currently visible in the region.
    #[serde(default)]
    pub cells: Vec<ServiceGroupDiscoveryCellProjection>,
}

/// Cross-cell and cross-region discovery projection for one logical service-group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceGroupDiscoveryRecord {
    /// Logical service-group identifier.
    pub group: String,
    /// Regions currently resolving at least one healthy registration for the group.
    #[serde(default)]
    pub healthy_regions: Vec<String>,
    /// Cells currently resolving at least one healthy registration for the group.
    #[serde(default)]
    pub healthy_cells: Vec<String>,
    /// Healthy registration identifiers currently resolved across all cells.
    #[serde(default)]
    pub resolved_registration_ids: Vec<String>,
    /// Region and cell slices currently contributing to discovery for the group.
    #[serde(default)]
    pub regions: Vec<ServiceGroupDiscoveryRegionProjection>,
    /// Earliest registration timestamp contributing to the current projection snapshot.
    pub registered_at: OffsetDateTime,
    /// Most recent source update timestamp contributing to the current projection snapshot.
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServiceGroupDiscoveryState {
    /// Most recent service-group directory cursor consumed into the discovery cache.
    #[serde(default)]
    pub service_group_directory_cursor: CellServiceGroupDirectoryCursor,
    /// Cell-scoped service-group directories currently cached for projection rebuilds.
    #[serde(default)]
    pub cached_cells: BTreeMap<String, CellServiceGroupDirectoryRecord>,
}

impl ServiceGroupDiscoveryState {
    fn restore_cached_cells_from_checkpoint(
        &mut self,
        checkpoint: CellServiceGroupDirectorySnapshotCheckpoint,
    ) {
        self.service_group_directory_cursor = checkpoint.cursor;
        self.cached_cells = checkpoint
            .records
            .into_iter()
            .filter_map(|(key, document)| (!document.deleted).then_some((key, document.value)))
            .collect();
    }
}

#[derive(Debug, Default)]
struct ServiceGroupDiscoveryProjectionBuilder {
    healthy_regions: BTreeSet<String>,
    healthy_cells: BTreeSet<String>,
    resolved_registration_ids: BTreeSet<String>,
    regions: BTreeMap<String, ServiceGroupDiscoveryRegionBuilder>,
    registered_at: Option<OffsetDateTime>,
    updated_at: Option<OffsetDateTime>,
}

#[derive(Debug, Default)]
struct ServiceGroupDiscoveryRegionBuilder {
    region_name: String,
    healthy_cells: BTreeSet<String>,
    cells: BTreeMap<String, ServiceGroupDiscoveryCellProjection>,
}

/// Watch-backed projector that materializes cross-cell and cross-region service-group discovery.
#[derive(Debug, Clone)]
pub struct ServiceGroupDiscoveryProjector {
    state_store: MetadataCollection<ServiceGroupDiscoveryState>,
}

impl ServiceGroupDiscoveryProjector {
    /// Wrap one durable state store behind the shared discovery-projector boundary.
    pub fn new(state_store: MetadataCollection<ServiceGroupDiscoveryState>) -> Self {
        Self { state_store }
    }

    /// Open the default file-backed discovery-projector state store for all-in-one mode.
    pub async fn open_local(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::new(MetadataCollection::open_local(path).await?))
    }

    /// Replay watched cell service-group changes and refresh the derived discovery cache.
    pub async fn refresh(
        &self,
        service_group_directory_store: &CellServiceGroupDirectoryCollection,
        discovery_store: &ServiceGroupDiscoveryCollection,
    ) -> Result<Vec<ServiceGroupDiscoveryRecord>> {
        let stored_state: Option<StoredDocument<ServiceGroupDiscoveryState>> = self
            .state_store
            .get(SERVICE_GROUP_DISCOVERY_STATE_KEY)
            .await?;
        let expected_version = stored_state.as_ref().map(|stored| stored.version);
        let mut state = stored_state
            .as_ref()
            .and_then(|stored| (!stored.deleted).then_some(stored.value.clone()))
            .unwrap_or_default();
        let original_state = state.clone();

        self.replay_service_group_directory_changes(service_group_directory_store, &mut state)
            .await?;

        let projections = resolve_service_group_discovery(state.cached_cells.values());
        sync_service_group_discovery_store(discovery_store, &projections).await?;

        if expected_version.is_none() || state != original_state {
            self.state_store
                .upsert(SERVICE_GROUP_DISCOVERY_STATE_KEY, state, expected_version)
                .await?;
        }

        Ok(projections)
    }

    async fn replay_service_group_directory_changes(
        &self,
        service_group_directory_store: &CellServiceGroupDirectoryCollection,
        state: &mut ServiceGroupDiscoveryState,
    ) -> Result<()> {
        replay_document_change_feed(
            state,
            state.service_group_directory_cursor,
            |cursor| {
                service_group_directory_store
                    .changes_since(cursor, SERVICE_GROUP_DISCOVERY_PAGE_LIMIT)
            },
            || service_group_directory_store.snapshot_checkpoint(),
            |state, cursor| state.service_group_directory_cursor = cursor,
            |state, changes| {
                for change in changes {
                    if change.document.deleted {
                        state.cached_cells.remove(change.key.as_str());
                    } else {
                        state.cached_cells.insert(change.key, change.document.value);
                    }
                }
                Ok(())
            },
            |state, checkpoint| {
                state.restore_cached_cells_from_checkpoint(checkpoint);
                Ok(())
            },
        )
        .await
    }
}

/// Build cross-cell and cross-region discovery projections from the cached cell directories.
pub fn resolve_service_group_discovery<'a, I>(
    cell_directories: I,
) -> Vec<ServiceGroupDiscoveryRecord>
where
    I: IntoIterator<Item = &'a CellServiceGroupDirectoryRecord>,
{
    let mut by_group = BTreeMap::<String, ServiceGroupDiscoveryProjectionBuilder>::new();
    for cell_directory in cell_directories {
        for entry in &cell_directory.groups {
            let group = trimmed_string(entry.group.clone());
            if group.is_empty() {
                continue;
            }

            let cell_projection = ServiceGroupDiscoveryCellProjection::from_cell_directory_entry(
                cell_directory,
                entry,
            );
            let builder = by_group.entry(group).or_default();
            builder.registered_at = Some(
                builder
                    .registered_at
                    .map_or(cell_directory.registered_at, |current| {
                        current.min(cell_directory.registered_at)
                    }),
            );
            builder.updated_at = Some(
                builder
                    .updated_at
                    .map_or(cell_directory.updated_at, |current| {
                        current.max(cell_directory.updated_at)
                    }),
            );
            builder
                .resolved_registration_ids
                .extend(cell_projection.resolved_registration_ids.iter().cloned());
            if !cell_projection.resolved_registration_ids.is_empty() {
                builder
                    .healthy_regions
                    .insert(trimmed_string(cell_directory.region.region_id.clone()));
                builder
                    .healthy_cells
                    .insert(trimmed_string(cell_directory.cell_id.clone()));
            }

            let region_id = trimmed_string(cell_directory.region.region_id.clone());
            let region_builder = builder.regions.entry(region_id).or_default();
            region_builder.region_name = trimmed_string(cell_directory.region.region_name.clone());
            if !cell_projection.resolved_registration_ids.is_empty() {
                region_builder
                    .healthy_cells
                    .insert(trimmed_string(cell_directory.cell_id.clone()));
            }
            region_builder
                .cells
                .insert(cell_projection.cell_id.clone(), cell_projection);
        }
    }

    by_group
        .into_iter()
        .map(|(group, builder)| ServiceGroupDiscoveryRecord {
            group,
            healthy_regions: builder.healthy_regions.into_iter().collect(),
            healthy_cells: builder.healthy_cells.into_iter().collect(),
            resolved_registration_ids: builder.resolved_registration_ids.into_iter().collect(),
            regions: builder
                .regions
                .into_iter()
                .map(
                    |(region_id, region)| ServiceGroupDiscoveryRegionProjection {
                        region_id,
                        region_name: region.region_name,
                        healthy_cells: region.healthy_cells.into_iter().collect(),
                        cells: region.cells.into_values().collect(),
                    },
                )
                .collect(),
            registered_at: builder
                .registered_at
                .unwrap_or_else(OffsetDateTime::now_utc),
            updated_at: builder.updated_at.unwrap_or_else(OffsetDateTime::now_utc),
        })
        .collect()
}

async fn sync_service_group_discovery_store(
    discovery_store: &ServiceGroupDiscoveryCollection,
    projections: &[ServiceGroupDiscoveryRecord],
) -> Result<()> {
    let mut existing = discovery_store
        .list()
        .await?
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    for projection in projections {
        match existing.remove(projection.group.as_str()) {
            Some(stored) if !stored.deleted && stored.value == *projection => {}
            Some(stored) => {
                discovery_store
                    .upsert(
                        projection.group.as_str(),
                        projection.clone(),
                        Some(stored.version),
                    )
                    .await?;
            }
            None => {
                discovery_store
                    .create(projection.group.as_str(), projection.clone())
                    .await?;
            }
        }
    }

    for (group, stored) in existing {
        if !stored.deleted {
            discovery_store
                .soft_delete(group.as_str(), Some(stored.version))
                .await?;
        }
    }

    Ok(())
}

/// Stable subject kinds that can own one durable global cell home.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellHomeSubjectKind {
    /// Tenant-level home assignment.
    Tenant,
    /// Project-level home assignment.
    Project,
    /// Workload-level home assignment.
    Workload,
    /// Deployment-level home assignment.
    Deployment,
    /// Service-shard-level home assignment.
    ServiceShard,
}

impl CellHomeSubjectKind {
    /// Borrow the stable snake_case label used in keys and reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Project => "project",
            Self::Workload => "workload",
            Self::Deployment => "deployment",
            Self::ServiceShard => "service_shard",
        }
    }
}

/// Hierarchical ancestry carried by one global cell-home projection record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CellHomeLineage {
    /// Stable tenant identifier when the subject is tenant-scoped or nested under one tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Stable project identifier when the subject is project-scoped or nested under one project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Stable workload identifier when the subject is workload-scoped or nested under one workload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    /// Stable deployment identifier when the subject is deployment-scoped or nested under one deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<String>,
    /// Stable service-shard identifier when the subject is service-shard-scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_shard_id: Option<String>,
}

/// Durable `(region, cell)` home carried by one global cell-home projection record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellHomeLocation {
    /// Stable cell identifier.
    pub cell_id: String,
    /// Human-meaningful cell name used by operators and reports.
    pub cell_name: String,
    /// Region membership for the home cell.
    pub region: RegionDirectoryRecord,
}

impl CellHomeLocation {
    /// Build one durable `(region, cell)` home snapshot.
    pub fn new(
        cell_id: impl Into<String>,
        cell_name: impl Into<String>,
        region: RegionDirectoryRecord,
    ) -> Self {
        Self {
            cell_id: trimmed_string(cell_id),
            cell_name: trimmed_string(cell_name),
            region,
        }
    }
}

/// One durable global projection that maps a logical subject to its owning `(region, cell)` home.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellHomeProjectionRecord {
    /// Subject family carried by this record.
    pub subject_kind: CellHomeSubjectKind,
    /// Stable identifier for the subject family carried by this record.
    pub subject_id: String,
    /// Hierarchical ancestry linking the subject back to tenant, project, workload, or deployment homes.
    pub lineage: CellHomeLineage,
    /// Owning `(region, cell)` home for the subject.
    pub home: CellHomeLocation,
    /// Timestamp when this home assignment was first published.
    pub registered_at: OffsetDateTime,
    /// Timestamp when this home assignment was most recently updated.
    pub updated_at: OffsetDateTime,
}

impl CellHomeProjectionRecord {
    /// Build one tenant home projection.
    pub fn tenant(tenant_id: impl Into<String>, home: CellHomeLocation) -> Self {
        let tenant_id = trimmed_string(tenant_id);
        Self::new(
            CellHomeSubjectKind::Tenant,
            tenant_id.clone(),
            CellHomeLineage {
                tenant_id: (!tenant_id.is_empty()).then_some(tenant_id),
                ..Default::default()
            },
            home,
        )
    }

    /// Build one project home projection nested under one tenant.
    pub fn project(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        home: CellHomeLocation,
    ) -> Self {
        let project_id = trimmed_string(project_id);
        Self::new(
            CellHomeSubjectKind::Project,
            project_id.clone(),
            CellHomeLineage {
                tenant_id: trimmed_optional_string(tenant_id),
                project_id: (!project_id.is_empty()).then_some(project_id),
                ..Default::default()
            },
            home,
        )
    }

    /// Build one workload home projection nested under one project.
    pub fn workload(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        workload_id: impl Into<String>,
        home: CellHomeLocation,
    ) -> Self {
        let workload_id = trimmed_string(workload_id);
        Self::new(
            CellHomeSubjectKind::Workload,
            workload_id.clone(),
            CellHomeLineage {
                tenant_id: trimmed_optional_string(tenant_id),
                project_id: trimmed_optional_string(project_id),
                workload_id: (!workload_id.is_empty()).then_some(workload_id),
                ..Default::default()
            },
            home,
        )
    }

    /// Build one deployment home projection nested under one workload.
    pub fn deployment(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        workload_id: impl Into<String>,
        deployment_id: impl Into<String>,
        home: CellHomeLocation,
    ) -> Self {
        let deployment_id = trimmed_string(deployment_id);
        Self::new(
            CellHomeSubjectKind::Deployment,
            deployment_id.clone(),
            CellHomeLineage {
                tenant_id: trimmed_optional_string(tenant_id),
                project_id: trimmed_optional_string(project_id),
                workload_id: trimmed_optional_string(workload_id),
                deployment_id: (!deployment_id.is_empty()).then_some(deployment_id),
                ..Default::default()
            },
            home,
        )
    }

    /// Build one service-shard home projection nested under one deployment.
    pub fn service_shard(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        workload_id: impl Into<String>,
        deployment_id: impl Into<String>,
        service_shard_id: impl Into<String>,
        home: CellHomeLocation,
    ) -> Self {
        let service_shard_id = trimmed_string(service_shard_id);
        Self::new(
            CellHomeSubjectKind::ServiceShard,
            service_shard_id.clone(),
            CellHomeLineage {
                tenant_id: trimmed_optional_string(tenant_id),
                project_id: trimmed_optional_string(project_id),
                workload_id: trimmed_optional_string(workload_id),
                deployment_id: trimmed_optional_string(deployment_id),
                service_shard_id: (!service_shard_id.is_empty()).then_some(service_shard_id),
            },
            home,
        )
    }

    /// Return the stable document key used to persist this projection record.
    pub fn key(&self) -> String {
        cell_home_projection_key(self.subject_kind, self.subject_id.clone())
    }

    /// Replace the owning `(region, cell)` home and refresh the update timestamp.
    pub fn set_home(&mut self, home: CellHomeLocation) {
        self.home = home;
        self.touch();
    }

    fn new(
        subject_kind: CellHomeSubjectKind,
        subject_id: String,
        lineage: CellHomeLineage,
        home: CellHomeLocation,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            subject_kind,
            subject_id,
            lineage,
            home,
            registered_at: now,
            updated_at: now,
        }
    }

    fn touch(&mut self) {
        self.updated_at = OffsetDateTime::now_utc();
    }
}

/// Return the stable document key for one global cell-home projection.
pub fn cell_home_projection_key(
    subject_kind: CellHomeSubjectKind,
    subject_id: impl Into<String>,
) -> String {
    format!("{}:{}", subject_kind.as_str(), trimmed_string(subject_id))
}

/// Stable cursor used to consume deterministic cell-home projection changes.
pub type CellHomeProjectionCursor = DocumentCursor;

/// One deterministic cell-home projection mutation snapshot.
pub type CellHomeProjectionChange = DocumentChange<CellHomeProjectionRecord>;

/// One ordered page of deterministic cell-home projection changes.
pub type CellHomeProjectionChangePage = DocumentChangePage<CellHomeProjectionRecord>;

/// File-backed cache of tenant, project, workload, deployment, and service-shard home assignments.
pub type CellHomeProjectionCollection = DocumentStore<CellHomeProjectionRecord>;

fn trimmed_string(value: impl Into<String>) -> String {
    value.into().trim().to_owned()
}

fn trimmed_optional_string(value: impl Into<String>) -> Option<String> {
    let value = trimmed_string(value);
    if value.is_empty() { None } else { Some(value) }
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

fn healthy_cell_service_group_participant_state(state: &CellParticipantState) -> bool {
    state.readiness == LeaseReadiness::Ready
        && state.drain_intent == LeaseDrainIntent::Serving
        && state.lease.freshness == LeaseFreshness::Fresh
}

fn cell_service_group_registration_base_health(
    registration: &CellServiceGroupRegistrationResolution,
) -> bool {
    if registration.readiness.is_some()
        || registration.drain_intent.is_some()
        || registration.lease_freshness.is_some()
    {
        registration.readiness == Some(LeaseReadiness::Ready)
            && registration.drain_intent == Some(LeaseDrainIntent::Serving)
            && registration.lease_freshness == Some(LeaseFreshness::Fresh)
    } else {
        registration.healthy
    }
}

fn quarantined_cell_service_group_registration_ids(
    registrations: &[CellServiceGroupRegistrationResolution],
    safety_policy: &BoundedContextSafetyPolicy,
) -> BTreeSet<String> {
    let healthy_registrations = registrations
        .iter()
        .filter(|registration| registration.healthy)
        .collect::<Vec<_>>();
    let mut quarantined_registration_ids = BTreeSet::new();

    if healthy_registrations.len() > 1 && !safety_policy.allows_parallel_healthy_registrations() {
        quarantined_registration_ids.extend(
            healthy_registrations
                .iter()
                .map(|registration| registration.registration_id.clone()),
        );
    }

    extend_quarantined_registration_ids_for_duplicate_value(
        &mut quarantined_registration_ids,
        &healthy_registrations,
        |registration| Some(registration.subject_id.as_str()),
    );
    extend_quarantined_registration_ids_for_duplicate_value(
        &mut quarantined_registration_ids,
        &healthy_registrations,
        |registration| registration.lease_registration_id.as_deref(),
    );

    quarantined_registration_ids
}

fn extend_quarantined_registration_ids_for_duplicate_value<F>(
    quarantined_registration_ids: &mut BTreeSet<String>,
    healthy_registrations: &[&CellServiceGroupRegistrationResolution],
    value_for: F,
) where
    F: Fn(&CellServiceGroupRegistrationResolution) -> Option<&str>,
{
    let mut registration_ids_by_value = BTreeMap::<String, Vec<String>>::new();

    for registration in healthy_registrations {
        let Some(value) = value_for(registration)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        registration_ids_by_value
            .entry(value.to_owned())
            .or_default()
            .push(registration.registration_id.clone());
    }

    for registration_ids in registration_ids_by_value.into_values() {
        if registration_ids.len() > 1 {
            quarantined_registration_ids.extend(registration_ids);
        }
    }
}

fn converge_cell_participant_at(
    participant: &CellParticipantRecord,
    linked_registration: Option<&LeaseRegistrationRecord>,
    observed_at: OffsetDateTime,
) -> CellParticipantRecord {
    match linked_registration {
        Some(registration)
            if !runtime_participant_registration_link_is_possible(participant, registration) =>
        {
            quarantine_runtime_participant_from_invalid_link_at(participant, observed_at)
        }
        Some(registration) => {
            converge_cell_participant_from_registration_at(participant, registration, observed_at)
        }
        None => converge_cell_participant_from_published_state_at(participant, observed_at),
    }
}

fn quarantine_runtime_participant_from_invalid_link_at(
    participant: &CellParticipantRecord,
    observed_at: OffsetDateTime,
) -> CellParticipantRecord {
    let Some(state) = participant.state.as_ref() else {
        return participant.clone();
    };

    let expires_at = if state.lease.expires_at > observed_at {
        observed_at
    } else {
        state.lease.expires_at
    };
    let renewed_at = if state.lease.renewed_at > expires_at {
        expires_at
    } else {
        state.lease.renewed_at
    };
    let mut quarantined = participant.clone();
    quarantined.state = Some(carry_forward_takeover_acknowledgement(
        participant.state.as_ref(),
        CellParticipantState::new(
            state.readiness,
            LeaseDrainIntent::Draining,
            CellParticipantLeaseState::new(
                renewed_at,
                expires_at,
                state.lease.duration_seconds,
                LeaseFreshness::Expired,
            ),
        )
        .with_published_drain_intent(state.published_drain_intent())
        .with_lease_source(CellParticipantLeaseSource::PublishedStateFallback),
    ));
    quarantined
}

fn converge_cell_participant_from_registration_at(
    participant: &CellParticipantRecord,
    registration: &LeaseRegistrationRecord,
    observed_at: OffsetDateTime,
) -> CellParticipantRecord {
    let freshness = registration.lease_freshness_at(observed_at);
    let mut converged = participant.clone();
    converged.participant_kind = trimmed_string(registration.subject_kind.clone());
    converged.subject_id = trimmed_string(registration.subject_id.clone());
    converged.role = trimmed_string(registration.role.clone());
    if let Some(node_name) = registration.node_name.clone() {
        converged.node_name = trimmed_optional_string(node_name);
    }
    converged.lease_registration_id = Some(trimmed_string(registration.registration_id.clone()));
    converged.registered_at = registration.registered_at;
    converged.state = Some(carry_forward_takeover_acknowledgement(
        participant.state.as_ref(),
        CellParticipantState::new(
            registration.readiness,
            degraded_drain_intent_for_freshness(registration.drain_intent, freshness),
            CellParticipantLeaseState::new(
                registration.lease_renewed_at,
                registration.lease_expires_at,
                registration.lease_duration_seconds,
                freshness,
            ),
        )
        .with_published_drain_intent(registration.drain_intent)
        .with_lease_source(CellParticipantLeaseSource::LinkedRegistration),
    ));
    converged
}

fn converge_cell_participant_from_published_state_at(
    participant: &CellParticipantRecord,
    observed_at: OffsetDateTime,
) -> CellParticipantRecord {
    let Some(state) = participant.state.as_ref() else {
        return participant.clone();
    };
    let freshness = published_lease_freshness_at(&state.lease, observed_at);
    let published_drain_intent = state.published_drain_intent();
    let drain_intent = degraded_drain_intent_for_freshness(published_drain_intent, freshness);
    if freshness == state.lease.freshness
        && drain_intent == state.drain_intent
        && state.published_drain_intent == Some(published_drain_intent)
    {
        return participant.clone();
    }

    let mut converged = participant.clone();
    converged.state = Some(carry_forward_takeover_acknowledgement(
        participant.state.as_ref(),
        CellParticipantState::new(
            state.readiness,
            drain_intent,
            CellParticipantLeaseState::new(
                state.lease.renewed_at,
                state.lease.expires_at,
                state.lease.duration_seconds,
                freshness,
            ),
        )
        .with_published_drain_intent(published_drain_intent)
        .with_lease_source(CellParticipantLeaseSource::PublishedStateFallback),
    ));
    converged
}

fn carry_forward_takeover_acknowledgement(
    previous: Option<&CellParticipantState>,
    mut next: CellParticipantState,
) -> CellParticipantState {
    if let Some(previous) = previous
        && let (Some(takeover_registration_id), Some(takeover_acknowledged_at)) = (
            previous.takeover_registration_id.clone(),
            previous.takeover_acknowledged_at,
        )
    {
        next =
            next.with_takeover_acknowledgement(takeover_registration_id, takeover_acknowledged_at);
    }
    next
}

fn published_lease_freshness_at(
    lease: &CellParticipantLeaseState,
    observed_at: OffsetDateTime,
) -> LeaseFreshness {
    if observed_at >= lease.expires_at {
        return LeaseFreshness::Expired;
    }

    let remaining = lease.expires_at - observed_at;
    if remaining <= published_stale_window(lease.duration_seconds) {
        LeaseFreshness::Stale
    } else {
        LeaseFreshness::Fresh
    }
}

fn published_stale_window(duration_seconds: u32) -> Duration {
    Duration::seconds(i64::from((duration_seconds.max(1) / 3).max(1)))
}

fn degraded_drain_intent_for_freshness(
    drain_intent: LeaseDrainIntent,
    freshness: LeaseFreshness,
) -> LeaseDrainIntent {
    match freshness {
        LeaseFreshness::Fresh => drain_intent,
        LeaseFreshness::Stale | LeaseFreshness::Expired => LeaseDrainIntent::Draining,
    }
}

fn degraded_reason_for_effective_state(
    drain_intent: LeaseDrainIntent,
    published_drain_intent: LeaseDrainIntent,
    freshness: LeaseFreshness,
) -> Option<CellParticipantDegradedReason> {
    if drain_intent != LeaseDrainIntent::Draining || published_drain_intent == drain_intent {
        return None;
    }

    match freshness {
        LeaseFreshness::Fresh => None,
        LeaseFreshness::Stale => Some(CellParticipantDegradedReason::LeaseStale),
        LeaseFreshness::Expired => Some(CellParticipantDegradedReason::LeaseExpired),
    }
}

#[cfg(test)]
mod tests {
    use time::{Duration, OffsetDateTime};

    use crate::lease::{LeaseDrainIntent, LeaseFreshness, LeaseReadiness, LeaseRegistrationRecord};

    use uhost_testkit::TempState;

    use super::{
        BoundedContextCoordinationModel, BoundedContextOwnershipScope, BoundedContextSafetyPolicy,
        BoundedContextSafetyRecord, CellDirectoryCollection, CellDirectoryRecord, CellHomeLocation,
        CellHomeProjectionCollection, CellHomeProjectionRecord, CellHomeSubjectKind,
        CellParticipantDegradedReason, CellParticipantDrainPhase, CellParticipantLeaseSource,
        CellParticipantLeaseState, CellParticipantReconciliationState, CellParticipantRecord,
        CellParticipantState, CellServiceGroupConflictState, CellServiceGroupDirectoryCollection,
        LocalCellRegistry, LocalCellRegistryPublication, LocalCellRegistryState,
        ParticipantTombstoneHistoryRecord, RegionDirectoryRecord, ServiceEndpointBinding,
        ServiceEndpointCollection, ServiceEndpointProtocol, ServiceEndpointRecord,
        ServiceGroupDiscoveryCollection, ServiceGroupDiscoveryProjector,
        ServiceGroupDiscoveryState, ServiceInstanceCollection, ServiceInstanceRecord,
        cell_home_projection_key, converge_cell_directory_participants_at,
        local_cell_registry_cache_snapshot_key, resolve_cell_service_group_directory,
        resolve_cell_service_group_directory_with_safety_matrix, resolve_cell_service_instances,
    };
    use crate::lease::LeaseRegistrationCollection;
    use crate::metadata::MetadataCollection;

    #[test]
    fn crate_root_reexports_registry_snapshot_checkpoint_aliases() {
        let root_cell_checkpoint: Option<crate::CellDirectorySnapshotCheckpoint> = None;
        let _module_cell_checkpoint: Option<super::CellDirectorySnapshotCheckpoint> =
            root_cell_checkpoint;

        let root_service_group_checkpoint: Option<
            crate::CellServiceGroupDirectorySnapshotCheckpoint,
        > = None;
        let _module_service_group_checkpoint: Option<
            super::CellServiceGroupDirectorySnapshotCheckpoint,
        > = root_service_group_checkpoint;
    }

    #[test]
    fn crate_root_reexports_registry_public_helper_types() {
        let root_route_withdrawal: crate::EvacuationRouteWithdrawalArtifact =
            super::EvacuationRouteWithdrawalArtifact::new(
                "local:cell-a",
                "controller:node-a",
                vec![String::from("control")],
                OffsetDateTime::UNIX_EPOCH,
            );
        let _module_route_withdrawal: super::EvacuationRouteWithdrawalArtifact =
            root_route_withdrawal;

        let root_target_readiness: crate::EvacuationTargetReadinessArtifact =
            super::EvacuationTargetReadinessArtifact::new(
                "local:cell-a",
                "controller:node-a",
                "worker:node-b",
                vec![String::from("control")],
                OffsetDateTime::UNIX_EPOCH,
            );
        let _module_target_readiness: super::EvacuationTargetReadinessArtifact =
            root_target_readiness;

        let root_rollback: crate::EvacuationRollbackArtifact =
            super::EvacuationRollbackArtifact::new(
                "local:cell-a",
                "controller:node-a",
                "worker:node-b",
                vec![String::from("control")],
                OffsetDateTime::UNIX_EPOCH,
            );
        let _module_rollback: super::EvacuationRollbackArtifact = root_rollback;

        let root_binding: crate::ServiceEndpointBinding = super::ServiceEndpointBinding::new(
            "edge",
            "127.0.0.1:8080",
            ServiceEndpointProtocol::Http,
        );
        let _module_binding: super::ServiceEndpointBinding = root_binding;

        let root_cache_snapshot: Option<crate::LocalCellRegistryCacheSnapshot> = None;
        let _module_cache_snapshot: Option<super::LocalCellRegistryCacheSnapshot> =
            root_cache_snapshot;
    }

    fn build_runtime_participant<I, S>(
        registration_id: &str,
        role: &str,
        node_name: &str,
        service_groups: I,
        readiness: LeaseReadiness,
        drain_intent: LeaseDrainIntent,
        freshness: LeaseFreshness,
        observed_at: OffsetDateTime,
    ) -> CellParticipantRecord
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let (renewed_at, expires_at) = match freshness {
            LeaseFreshness::Fresh => (
                observed_at - Duration::seconds(1),
                observed_at + Duration::seconds(30),
            ),
            LeaseFreshness::Stale => (
                observed_at - Duration::seconds(10),
                observed_at + Duration::seconds(4),
            ),
            LeaseFreshness::Expired => (
                observed_at - Duration::seconds(45),
                observed_at - Duration::seconds(30),
            ),
        };
        CellParticipantRecord::new(registration_id, "runtime_process", registration_id, role)
            .with_node_name(node_name)
            .with_service_groups(service_groups)
            .with_lease_registration_id(registration_id)
            .with_state(CellParticipantState::new(
                readiness,
                drain_intent,
                CellParticipantLeaseState::new(renewed_at, expires_at, 15, freshness),
            ))
    }

    fn build_cell_service_group_directory(
        cell_id: &str,
        cell_name: &str,
        region_id: &str,
        region_name: &str,
        participants: Vec<CellParticipantRecord>,
    ) -> super::CellServiceGroupDirectoryRecord {
        let directory = participants.into_iter().fold(
            CellDirectoryRecord::new(
                cell_id,
                cell_name,
                RegionDirectoryRecord::new(region_id, region_name),
            ),
            |directory, participant| directory.with_participant(participant),
        );
        resolve_cell_service_group_directory(&directory)
    }

    #[tokio::test]
    async fn local_cell_directory_collection_persists_region_membership_and_participants() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let path = state
            .checked_join("cells.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_a = CellDirectoryCollection::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_b = CellDirectoryCollection::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let created = collection_a
            .upsert(
                "local:local-cell",
                CellDirectoryRecord::new(
                    "local:local-cell",
                    "local-cell",
                    RegionDirectoryRecord::new("local", "local"),
                )
                .with_participant(
                    CellParticipantRecord::new(
                        "all_in_one:node-a",
                        "runtime_process",
                        "all_in_one:node-a",
                        "all_in_one",
                    )
                    .with_node_name("node-a")
                    .with_service_groups(["edge", "uvm"])
                    .with_lease_registration_id("all_in_one:node-a")
                    .with_state(CellParticipantState::new(
                        LeaseReadiness::Ready,
                        LeaseDrainIntent::Serving,
                        CellParticipantLeaseState::new(
                            time::OffsetDateTime::now_utc(),
                            time::OffsetDateTime::now_utc() + time::Duration::seconds(15),
                            15,
                            LeaseFreshness::Fresh,
                        ),
                    )),
                ),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut updated_record = collection_b
            .get("local:local-cell")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing durable cell directory"))
            .value;
        updated_record.upsert_participant(
            CellParticipantRecord::new(
                "controller:node-b",
                "runtime_process",
                "controller:node-b",
                "controller",
            )
            .with_node_name("node-b")
            .with_service_groups(["control"]),
        );

        let updated = collection_b
            .upsert("local:local-cell", updated_record, Some(created.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let loaded = collection_a
            .get("local:local-cell")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing durable cell directory after update"));
        assert_eq!(loaded.version, updated.version);
        assert_eq!(loaded.value.cell_id, "local:local-cell");
        assert_eq!(loaded.value.cell_name, "local-cell");
        assert_eq!(loaded.value.region.region_id, "local");
        assert_eq!(loaded.value.region.region_name, "local");
        assert_eq!(loaded.value.participants.len(), 2);
        assert_eq!(
            loaded.value.participants[0].registration_id,
            "all_in_one:node-a"
        );
        assert_eq!(
            loaded.value.participants[0]
                .lease_registration_id
                .as_deref(),
            Some("all_in_one:node-a")
        );
        let state = loaded.value.participants[0]
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing participant state"));
        assert_eq!(state.readiness, LeaseReadiness::Ready);
        assert_eq!(state.drain_intent, LeaseDrainIntent::Serving);
        assert_eq!(state.published_drain_intent(), LeaseDrainIntent::Serving);
        assert_eq!(state.drain_phase, CellParticipantDrainPhase::Serving);
        assert!(state.takeover_registration_id.is_none());
        assert!(state.takeover_acknowledged_at.is_none());
        assert!(state.degraded_reason.is_none());
        assert_eq!(
            state.lease_source,
            CellParticipantLeaseSource::PublishedStateFallback
        );
        assert_eq!(state.lease.duration_seconds, 15);
        assert_eq!(state.lease.freshness, LeaseFreshness::Fresh);
        assert_eq!(
            loaded.value.participants[1].registration_id,
            "controller:node-b"
        );
        assert_eq!(loaded.value.participants[1].service_groups, vec!["control"]);
    }

    #[tokio::test]
    async fn local_cell_directory_collection_replays_changes_from_cursor() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let path = state
            .checked_join("cells.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_a = CellDirectoryCollection::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_b = CellDirectoryCollection::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let origin = collection_a
            .current_cursor()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created = collection_a
            .upsert(
                "local:local-cell",
                CellDirectoryRecord::new(
                    "local:local-cell",
                    "local-cell",
                    RegionDirectoryRecord::new("local", "local"),
                )
                .with_participant(
                    CellParticipantRecord::new(
                        "all_in_one:node-a",
                        "runtime_process",
                        "all_in_one:node-a",
                        "all_in_one",
                    )
                    .with_node_name("node-a")
                    .with_service_groups(["edge", "uvm"]),
                ),
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
        assert_eq!(first_page.changes[0].key, "local:local-cell");
        assert_eq!(first_page.changes[0].document.version, 1);
        assert!(!first_page.changes[0].document.deleted);
        assert_eq!(first_page.changes[0].document.value.cell_name, "local-cell");
        assert_eq!(first_page.changes[0].document.value.participants.len(), 1);
        assert_eq!(first_page.next_cursor.revision, 1);

        let mut updated_record = created.value.clone();
        updated_record.set_cell_name("local-cell-v2");
        updated_record.upsert_participant(
            CellParticipantRecord::new(
                "controller:node-b",
                "runtime_process",
                "controller:node-b",
                "controller",
            )
            .with_node_name("node-b")
            .with_service_groups(["control"]),
        );
        let updated = collection_a
            .upsert("local:local-cell", updated_record, Some(created.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        collection_a
            .soft_delete("local:local-cell", Some(updated.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let second_page = collection_b
            .changes_since(Some(first_page.next_cursor), 10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second_page.changes.len(), 2);
        assert_eq!(second_page.changes[0].revision, 2);
        assert_eq!(second_page.changes[0].document.version, 2);
        assert!(!second_page.changes[0].document.deleted);
        assert_eq!(
            second_page.changes[0].document.value.cell_name,
            "local-cell-v2"
        );
        assert_eq!(second_page.changes[0].document.value.participants.len(), 2);
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

    #[tokio::test]
    async fn local_service_group_directory_collection_persists_resolved_groups() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let path = state
            .checked_join("service-groups.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_a = CellServiceGroupDirectoryCollection::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_b = CellServiceGroupDirectoryCollection::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let now = OffsetDateTime::now_utc();
        let directory = CellDirectoryRecord::new(
            "local:local-cell",
            "local-cell",
            RegionDirectoryRecord::new("local", "local"),
        )
        .with_participant(
            CellParticipantRecord::new(
                "all_in_one:node-a",
                "runtime_process",
                "all_in_one:node-a",
                "all_in_one",
            )
            .with_node_name("node-a")
            .with_service_groups(["edge"])
            .with_lease_registration_id("all_in_one:node-a")
            .with_state(CellParticipantState::new(
                LeaseReadiness::Ready,
                LeaseDrainIntent::Serving,
                CellParticipantLeaseState::new(
                    now,
                    now + Duration::seconds(15),
                    15,
                    LeaseFreshness::Fresh,
                ),
            )),
        )
        .with_participant(
            CellParticipantRecord::new(
                "controller:node-b",
                "runtime_process",
                "controller:node-b",
                "controller",
            )
            .with_node_name("node-b")
            .with_service_groups(["control"])
            .with_lease_registration_id("controller:node-b")
            .with_state(CellParticipantState::new(
                LeaseReadiness::Ready,
                LeaseDrainIntent::Serving,
                CellParticipantLeaseState::new(
                    now,
                    now + Duration::seconds(15),
                    15,
                    LeaseFreshness::Fresh,
                ),
            )),
        );
        let resolved = resolve_cell_service_group_directory(&directory);

        let created = collection_a
            .create("local:local-cell", resolved)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let loaded = collection_b
            .get("local:local-cell")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing durable service-group directory"));

        assert_eq!(loaded.version, created.version);
        assert_eq!(loaded.value.cell_id, "local:local-cell");
        assert_eq!(loaded.value.region.region_id, "local");
        assert_eq!(loaded.value.groups.len(), 2);
        let edge = loaded
            .value
            .groups
            .iter()
            .find(|entry| entry.group == "edge")
            .unwrap_or_else(|| panic!("missing edge service-group directory entry"));
        assert_eq!(
            edge.resolved_registration_ids,
            vec![String::from("all_in_one:node-a")]
        );
        assert_eq!(
            edge.conflict_state,
            CellServiceGroupConflictState::NoConflict
        );
        assert_eq!(
            edge.safety_policy.coordination_model,
            BoundedContextCoordinationModel::ActivePassiveRegional
        );
        assert_eq!(edge.registrations.len(), 1);
        assert!(edge.registrations[0].healthy);
        assert_eq!(
            edge.registrations[0].drain_intent,
            Some(LeaseDrainIntent::Serving)
        );
        assert_eq!(
            edge.registrations[0].lease_freshness,
            Some(LeaseFreshness::Fresh)
        );
    }

    #[test]
    fn service_group_directory_marks_healthy_registrations_and_conflicts() {
        let now = OffsetDateTime::now_utc();
        let healthy_a = CellParticipantRecord::new(
            "controller:node-a",
            "runtime_process",
            "controller:node-a",
            "controller",
        )
        .with_node_name("node-a")
        .with_service_groups(["control"])
        .with_lease_registration_id("controller:node-a")
        .with_state(CellParticipantState::new(
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            CellParticipantLeaseState::new(
                now,
                now + Duration::seconds(15),
                15,
                LeaseFreshness::Fresh,
            ),
        ));
        let healthy_b = CellParticipantRecord::new(
            "worker:node-b",
            "runtime_process",
            "worker:node-b",
            "worker",
        )
        .with_node_name("node-b")
        .with_service_groups(["control"])
        .with_lease_registration_id("worker:node-b")
        .with_state(CellParticipantState::new(
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            CellParticipantLeaseState::new(
                now,
                now + Duration::seconds(15),
                15,
                LeaseFreshness::Fresh,
            ),
        ));
        let unhealthy =
            CellParticipantRecord::new("edge:node-c", "runtime_process", "edge:node-c", "edge")
                .with_node_name("node-c")
                .with_service_groups(["edge"])
                .with_lease_registration_id("edge:node-c")
                .with_state(
                    CellParticipantState::new(
                        LeaseReadiness::Ready,
                        LeaseDrainIntent::Draining,
                        CellParticipantLeaseState::new(
                            now - Duration::seconds(10),
                            now - Duration::seconds(1),
                            15,
                            LeaseFreshness::Expired,
                        ),
                    )
                    .with_published_drain_intent(LeaseDrainIntent::Serving),
                );
        let directory = CellDirectoryRecord::new(
            "local:local-cell",
            "local-cell",
            RegionDirectoryRecord::new("local", "local"),
        )
        .with_participant(healthy_a)
        .with_participant(healthy_b)
        .with_participant(unhealthy);

        let resolved = resolve_cell_service_group_directory(&directory);

        assert_eq!(resolved.cell_id, "local:local-cell");
        assert_eq!(resolved.groups.len(), 2);
        let control = resolved
            .groups
            .iter()
            .find(|entry| entry.group == "control")
            .unwrap_or_else(|| panic!("missing control service-group entry"));
        let edge = resolved
            .groups
            .iter()
            .find(|entry| entry.group == "edge")
            .unwrap_or_else(|| panic!("missing edge service-group entry"));

        assert_eq!(control.resolved_registration_ids, Vec::<String>::new());
        assert_eq!(
            control.conflict_state,
            CellServiceGroupConflictState::MultipleHealthyRegistrations
        );
        assert_eq!(
            control.safety_policy.coordination_model,
            BoundedContextCoordinationModel::ActivePassiveRegional
        );
        assert_eq!(control.registrations.len(), 2);
        assert!(
            control
                .registrations
                .iter()
                .all(|registration| !registration.healthy)
        );
        assert_eq!(edge.resolved_registration_ids, Vec::<String>::new());
        assert_eq!(
            edge.conflict_state,
            CellServiceGroupConflictState::NoConflict
        );
        assert_eq!(edge.registrations.len(), 1);
        assert!(!edge.registrations[0].healthy);
        assert_eq!(
            edge.registrations[0].drain_intent,
            Some(LeaseDrainIntent::Draining)
        );
        assert_eq!(
            edge.registrations[0].lease_freshness,
            Some(LeaseFreshness::Expired)
        );
    }

    #[test]
    fn service_group_directory_applies_bounded_context_safety_matrix_overrides() {
        let now = OffsetDateTime::now_utc();
        let directory = CellDirectoryRecord::new(
            "local:local-cell",
            "local-cell",
            RegionDirectoryRecord::new("local", "local"),
        )
        .with_participant(build_runtime_participant(
            "data:node-a",
            "data_primary_a",
            "node-a",
            ["data_and_messaging"],
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            LeaseFreshness::Fresh,
            now,
        ))
        .with_participant(build_runtime_participant(
            "data:node-b",
            "data_primary_b",
            "node-b",
            ["data_and_messaging"],
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            LeaseFreshness::Fresh,
            now,
        ));
        let safety_rows = [BoundedContextSafetyRecord::new(
            "data_and_messaging",
            BoundedContextSafetyPolicy::new(
                BoundedContextCoordinationModel::ActiveActiveShardScoped,
            )
            .with_ownership_scope(BoundedContextOwnershipScope::ServiceShard)
            .with_fencing_requirement(true)
            .with_notes(["fenced shard home"]),
        )];

        let resolved =
            resolve_cell_service_group_directory_with_safety_matrix(&directory, safety_rows.iter());
        let data = resolved
            .groups
            .iter()
            .find(|entry| entry.group == "data_and_messaging")
            .unwrap_or_else(|| panic!("missing data_and_messaging service-group entry"));

        assert_eq!(
            data.conflict_state,
            CellServiceGroupConflictState::NoConflict
        );
        assert_eq!(
            data.resolved_registration_ids,
            vec![String::from("data:node-a"), String::from("data:node-b")]
        );
        assert_eq!(
            data.safety_policy.coordination_model,
            BoundedContextCoordinationModel::ActiveActiveShardScoped
        );
        assert_eq!(
            data.safety_policy.ownership_scope,
            BoundedContextOwnershipScope::ServiceShard
        );
        assert!(data.safety_policy.requires_fencing);
        assert!(!data.safety_policy.requires_quorum);
        assert_eq!(
            data.safety_policy.notes,
            vec![String::from("fenced shard home")]
        );
    }

    #[test]
    fn service_group_directory_quarantines_duplicate_subjects_even_when_parallel_healthy_allowed() {
        let now = OffsetDateTime::now_utc();
        let shared_subject_a = CellParticipantRecord::new(
            "observe:node-a",
            "runtime_process",
            "observe-shared-subject",
            "observe",
        )
        .with_node_name("node-a")
        .with_service_groups(["governance_and_operations"])
        .with_lease_registration_id("observe:node-a")
        .with_state(CellParticipantState::new(
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            CellParticipantLeaseState::new(
                now,
                now + Duration::seconds(15),
                15,
                LeaseFreshness::Fresh,
            ),
        ));
        let shared_subject_b = CellParticipantRecord::new(
            "observe:node-b",
            "runtime_process",
            "observe-shared-subject",
            "observe",
        )
        .with_node_name("node-b")
        .with_service_groups(["governance_and_operations"])
        .with_lease_registration_id("observe:node-b")
        .with_state(CellParticipantState::new(
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            CellParticipantLeaseState::new(
                now,
                now + Duration::seconds(15),
                15,
                LeaseFreshness::Fresh,
            ),
        ));
        let unique_subject = CellParticipantRecord::new(
            "observe:node-c",
            "runtime_process",
            "observe-unique-subject",
            "observe",
        )
        .with_node_name("node-c")
        .with_service_groups(["governance_and_operations"])
        .with_lease_registration_id("observe:node-c")
        .with_state(CellParticipantState::new(
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            CellParticipantLeaseState::new(
                now,
                now + Duration::seconds(15),
                15,
                LeaseFreshness::Fresh,
            ),
        ));
        let directory = CellDirectoryRecord::new(
            "local:local-cell",
            "local-cell",
            RegionDirectoryRecord::new("local", "local"),
        )
        .with_participant(shared_subject_a)
        .with_participant(shared_subject_b)
        .with_participant(unique_subject);
        let safety_rows = [BoundedContextSafetyRecord::new(
            "governance_and_operations",
            BoundedContextSafetyPolicy::new(BoundedContextCoordinationModel::ActiveActiveReadOnly),
        )];

        let resolved =
            resolve_cell_service_group_directory_with_safety_matrix(&directory, safety_rows.iter());
        let governance = resolved
            .groups
            .iter()
            .find(|entry| entry.group == "governance_and_operations")
            .unwrap_or_else(|| panic!("missing governance_and_operations service-group entry"));

        assert_eq!(
            governance.conflict_state,
            CellServiceGroupConflictState::MultipleHealthyRegistrations
        );
        assert_eq!(
            governance.resolved_registration_ids,
            vec![String::from("observe:node-c")]
        );

        let shared_subject_a = governance
            .registrations
            .iter()
            .find(|registration| registration.registration_id == "observe:node-a")
            .unwrap_or_else(|| panic!("missing observe:node-a registration"));
        let shared_subject_b = governance
            .registrations
            .iter()
            .find(|registration| registration.registration_id == "observe:node-b")
            .unwrap_or_else(|| panic!("missing observe:node-b registration"));
        let unique_subject = governance
            .registrations
            .iter()
            .find(|registration| registration.registration_id == "observe:node-c")
            .unwrap_or_else(|| panic!("missing observe:node-c registration"));

        assert!(!shared_subject_a.healthy);
        assert!(!shared_subject_b.healthy);
        assert!(unique_subject.healthy);
    }

    #[test]
    fn runtime_participant_conflict_detection_flags_duplicate_lease_links_even_without_service_group_overlap()
     {
        let now = OffsetDateTime::now_utc();
        let control = build_runtime_participant(
            "controller:node-a",
            "controller",
            "node-a",
            ["control"],
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            LeaseFreshness::Fresh,
            now,
        )
        .with_lease_registration_id("runtime:shared-node");
        let data = build_runtime_participant(
            "worker:node-a",
            "worker",
            "node-a",
            ["data_and_messaging"],
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            LeaseFreshness::Fresh,
            now,
        )
        .with_lease_registration_id("runtime:shared-node");

        let conflicts = super::conflicting_runtime_participant_registration_ids(&[control, data])
            .into_iter()
            .collect::<Vec<_>>();

        assert_eq!(
            conflicts,
            vec![
                String::from("controller:node-a"),
                String::from("worker:node-a")
            ]
        );
    }

    #[tokio::test]
    async fn service_instance_collection_persists_projected_records() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let path = state
            .checked_join("service-instances.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_a = ServiceInstanceCollection::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_b = ServiceInstanceCollection::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let now = OffsetDateTime::now_utc();
        let participant = CellParticipantRecord::new(
            "controller:node-a",
            "runtime_process",
            "controller:node-a",
            "controller",
        )
        .with_node_name("node-a")
        .with_service_groups(["control", "control"])
        .with_lease_registration_id(" controller:node-a ")
        .with_state(CellParticipantState::new(
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            CellParticipantLeaseState::new(
                now,
                now + Duration::seconds(15),
                15,
                LeaseFreshness::Fresh,
            ),
        ));
        let directory = CellDirectoryRecord::new(
            "local:cell-a",
            "cell-a",
            RegionDirectoryRecord::new("local", "local"),
        )
        .with_participant(participant);

        let projected = resolve_cell_service_instances(&directory, 7);
        assert_eq!(projected.len(), 1);
        let instance = projected
            .first()
            .cloned()
            .unwrap_or_else(|| panic!("missing projected service instance"));
        assert_eq!(instance.service_instance_id, "control:controller:node-a");
        assert_eq!(instance.cell_id, "local:cell-a");
        assert_eq!(instance.service_group, "control");
        assert_eq!(instance.participant_registration_id, "controller:node-a");
        assert_eq!(instance.node_name.as_deref(), Some("node-a"));
        assert_eq!(instance.readiness, Some(LeaseReadiness::Ready));
        assert_eq!(instance.drain_intent, Some(LeaseDrainIntent::Serving));
        assert_eq!(instance.lease_freshness, Some(LeaseFreshness::Fresh));
        assert_eq!(instance.revision, 7);
        assert_eq!(
            instance.linked_lease_ids,
            vec![String::from("controller:node-a")]
        );

        let created = collection_a
            .create(instance.service_instance_id.as_str(), instance.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let loaded = collection_b
            .get(instance.service_instance_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted service instance"));

        assert_eq!(loaded.version, created.version);
        assert_eq!(loaded.value, instance);
    }

    #[tokio::test]
    async fn service_endpoint_collection_persists_address_protocol_and_lease_links() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let path = state
            .checked_join("service-endpoints.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_a = ServiceEndpointCollection::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_b = ServiceEndpointCollection::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let now = OffsetDateTime::now_utc();
        let instance = resolve_cell_service_instances(
            &CellDirectoryRecord::new(
                "local:cell-b",
                "cell-b",
                RegionDirectoryRecord::new("local", "local"),
            )
            .with_participant(
                CellParticipantRecord::new("edge:node-b", "runtime_process", "edge:node-b", "edge")
                    .with_node_name("node-b")
                    .with_service_groups(["edge"])
                    .with_lease_registration_id("edge:node-b")
                    .with_state(CellParticipantState::new(
                        LeaseReadiness::Ready,
                        LeaseDrainIntent::Serving,
                        CellParticipantLeaseState::new(
                            now,
                            now + Duration::seconds(15),
                            15,
                            LeaseFreshness::Fresh,
                        ),
                    )),
            ),
            11,
        )
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing projected edge service instance"));
        let endpoint = ServiceEndpointRecord::from_service_instance(
            &instance,
            "127.0.0.1:9443",
            ServiceEndpointProtocol::Https,
        );

        assert_eq!(
            endpoint.service_endpoint_id,
            "edge:edge:node-b:https:127.0.0.1:9443"
        );
        assert_eq!(endpoint.service_instance_id, "edge:edge:node-b");
        assert_eq!(endpoint.cell_id, "local:cell-b");
        assert_eq!(endpoint.service_group, "edge");
        assert_eq!(endpoint.participant_registration_id, "edge:node-b");
        assert_eq!(endpoint.node_name.as_deref(), Some("node-b"));
        assert_eq!(endpoint.address, "127.0.0.1:9443");
        assert_eq!(endpoint.protocol, ServiceEndpointProtocol::Https);
        assert_eq!(endpoint.readiness, Some(LeaseReadiness::Ready));
        assert_eq!(endpoint.drain_intent, Some(LeaseDrainIntent::Serving));
        assert_eq!(endpoint.lease_freshness, Some(LeaseFreshness::Fresh));
        assert_eq!(endpoint.revision, 11);
        assert_eq!(endpoint.linked_lease_ids, vec![String::from("edge:node-b")]);

        let created = collection_a
            .create(endpoint.service_endpoint_id.as_str(), endpoint.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let loaded = collection_b
            .get(endpoint.service_endpoint_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted service endpoint"));

        assert_eq!(loaded.version, created.version);
        assert_eq!(loaded.value, endpoint);
    }

    #[test]
    fn convergence_marks_linked_expired_peer_as_draining() {
        let now = OffsetDateTime::now_utc();
        let registration_id = "controller:node-b";
        let mut linked_registration = LeaseRegistrationRecord::new(
            registration_id,
            "runtime_process",
            registration_id,
            "controller",
            Some(String::from("node-b")),
            15,
        )
        .with_readiness(LeaseReadiness::Ready)
        .with_drain_intent(LeaseDrainIntent::Serving);
        linked_registration.lease_renewed_at = now - Duration::seconds(45);
        linked_registration.lease_expires_at = now - Duration::seconds(30);

        let participant = CellParticipantRecord::new(
            registration_id,
            "runtime_process",
            registration_id,
            "controller",
        )
        .with_node_name("node-b")
        .with_service_groups(["control"])
        .with_lease_registration_id(registration_id)
        .with_state(CellParticipantState::new(
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            CellParticipantLeaseState::new(
                now - Duration::seconds(1),
                now + Duration::seconds(30),
                15,
                LeaseFreshness::Fresh,
            ),
        ));
        let directory = CellDirectoryRecord::new(
            "local:local-cell",
            "local-cell",
            RegionDirectoryRecord::new("local", "local"),
        )
        .with_participant(participant);

        let converged =
            converge_cell_directory_participants_at(&directory, [&linked_registration], now);
        let participant = converged
            .participants
            .first()
            .unwrap_or_else(|| panic!("missing converged participant"));
        let state = participant
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing converged participant state"));
        assert_eq!(state.readiness, LeaseReadiness::Ready);
        assert_eq!(state.drain_intent, LeaseDrainIntent::Draining);
        assert_eq!(state.published_drain_intent(), LeaseDrainIntent::Serving);
        assert_eq!(state.drain_phase, CellParticipantDrainPhase::Serving);
        assert!(state.takeover_registration_id.is_none());
        assert!(state.takeover_acknowledged_at.is_none());
        assert_eq!(
            state.degraded_reason,
            Some(CellParticipantDegradedReason::LeaseExpired)
        );
        assert_eq!(
            state.lease_source,
            CellParticipantLeaseSource::LinkedRegistration
        );
        assert_eq!(state.lease.freshness, LeaseFreshness::Expired);
        assert_eq!(participant.node_name.as_deref(), Some("node-b"));
        assert_eq!(
            participant.lease_registration_id.as_deref(),
            Some(registration_id)
        );
    }

    #[test]
    fn convergence_marks_linked_stale_peer_with_lease_stale_reason() {
        let now = OffsetDateTime::now_utc();
        let registration_id = "controller:node-c";
        let mut linked_registration = LeaseRegistrationRecord::new(
            registration_id,
            "runtime_process",
            registration_id,
            "controller",
            Some(String::from("node-c")),
            15,
        )
        .with_readiness(LeaseReadiness::Ready)
        .with_drain_intent(LeaseDrainIntent::Serving);
        linked_registration.lease_renewed_at = now - Duration::seconds(11);
        linked_registration.lease_expires_at = now + Duration::seconds(4);

        let participant = CellParticipantRecord::new(
            registration_id,
            "runtime_process",
            registration_id,
            "controller",
        )
        .with_node_name("node-c")
        .with_service_groups(["control"])
        .with_lease_registration_id(registration_id)
        .with_state(CellParticipantState::new(
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            CellParticipantLeaseState::new(
                now - Duration::seconds(1),
                now + Duration::seconds(30),
                15,
                LeaseFreshness::Fresh,
            ),
        ));
        let directory = CellDirectoryRecord::new(
            "local:local-cell",
            "local-cell",
            RegionDirectoryRecord::new("local", "local"),
        )
        .with_participant(participant);

        let converged =
            converge_cell_directory_participants_at(&directory, [&linked_registration], now);
        let state = converged.participants[0]
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing stale participant state"));

        assert_eq!(state.drain_intent, LeaseDrainIntent::Draining);
        assert_eq!(state.published_drain_intent(), LeaseDrainIntent::Serving);
        assert_eq!(state.drain_phase, CellParticipantDrainPhase::Serving);
        assert!(state.takeover_registration_id.is_none());
        assert!(state.takeover_acknowledged_at.is_none());
        assert_eq!(
            state.degraded_reason,
            Some(CellParticipantDegradedReason::LeaseStale)
        );
        assert_eq!(state.lease.freshness, LeaseFreshness::Stale);
    }

    #[test]
    fn convergence_falls_back_to_published_lease_window_when_linked_lease_is_missing() {
        let now = OffsetDateTime::now_utc();
        let participant = CellParticipantRecord::new(
            "controller:node-b",
            "runtime_process",
            "controller:node-b",
            "controller",
        )
        .with_node_name("node-b")
        .with_service_groups(["control"])
        .with_state(CellParticipantState::new(
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            CellParticipantLeaseState::new(
                now - Duration::seconds(60),
                now - Duration::seconds(5),
                15,
                LeaseFreshness::Fresh,
            ),
        ));
        let directory = CellDirectoryRecord::new(
            "local:local-cell",
            "local-cell",
            RegionDirectoryRecord::new("local", "local"),
        )
        .with_participant(participant);

        let converged = converge_cell_directory_participants_at(
            &directory,
            std::iter::empty::<&LeaseRegistrationRecord>(),
            now,
        );
        let state = converged.participants[0]
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing fallback-converged participant state"));
        assert_eq!(state.readiness, LeaseReadiness::Ready);
        assert_eq!(state.drain_intent, LeaseDrainIntent::Draining);
        assert_eq!(state.published_drain_intent(), LeaseDrainIntent::Serving);
        assert_eq!(state.drain_phase, CellParticipantDrainPhase::Serving);
        assert!(state.takeover_registration_id.is_none());
        assert!(state.takeover_acknowledged_at.is_none());
        assert_eq!(
            state.degraded_reason,
            Some(CellParticipantDegradedReason::LeaseExpired)
        );
        assert_eq!(
            state.lease_source,
            CellParticipantLeaseSource::PublishedStateFallback
        );
        assert_eq!(state.lease.freshness, LeaseFreshness::Expired);
    }

    #[test]
    fn participant_tombstone_history_record_captures_published_state_context() {
        let now = OffsetDateTime::now_utc();
        let participant = CellParticipantRecord::new(
            "controller:node-d",
            "runtime_process",
            "controller:node-d",
            "controller",
        )
        .with_lease_registration_id("controller:node-d")
        .with_state(
            CellParticipantState::new(
                LeaseReadiness::Ready,
                LeaseDrainIntent::Draining,
                CellParticipantLeaseState::new(
                    now - Duration::seconds(45),
                    now - Duration::seconds(30),
                    15,
                    LeaseFreshness::Expired,
                ),
            )
            .with_published_drain_intent(LeaseDrainIntent::Serving)
            .with_lease_source(CellParticipantLeaseSource::PublishedStateFallback),
        );

        let history = ParticipantTombstoneHistoryRecord::new(
            "aud_abcdefghijklmnopqrstuv",
            &participant,
            "stale-participant-cleanup:local:local-cell:controller:node-d",
            now,
            "bootstrap_admin",
            "operator",
            "corr-node-d",
        );

        assert_eq!(
            history.published_drain_intent,
            Some(LeaseDrainIntent::Serving)
        );
        assert_eq!(
            history.degraded_reason,
            Some(CellParticipantDegradedReason::LeaseExpired)
        );
        assert_eq!(
            history.lease_source,
            Some(CellParticipantLeaseSource::PublishedStateFallback)
        );
    }

    #[test]
    fn convergence_backfills_missing_published_drain_intent_for_legacy_published_state() {
        let now = OffsetDateTime::now_utc();
        let mut participant = CellParticipantRecord::new(
            "controller:legacy-node-b",
            "runtime_process",
            "controller:legacy-node-b",
            "controller",
        )
        .with_node_name("legacy-node-b")
        .with_service_groups(["control"])
        .with_state(CellParticipantState::new(
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            CellParticipantLeaseState::new(
                now - Duration::seconds(45),
                now - Duration::seconds(30),
                15,
                LeaseFreshness::Fresh,
            ),
        ));
        participant
            .state
            .as_mut()
            .unwrap_or_else(|| panic!("missing legacy participant state"))
            .published_drain_intent = None;

        let directory = CellDirectoryRecord::new(
            "local:cell-a",
            "cell-a",
            RegionDirectoryRecord::new("local", "local"),
        )
        .with_participant(participant);

        let converged = converge_cell_directory_participants_at(
            &directory,
            std::iter::empty::<&LeaseRegistrationRecord>(),
            now,
        );
        let state = converged.participants[0]
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing backfilled participant state"));

        assert_eq!(state.readiness, LeaseReadiness::Ready);
        assert_eq!(state.drain_intent, LeaseDrainIntent::Draining);
        assert_eq!(
            state.published_drain_intent,
            Some(LeaseDrainIntent::Serving)
        );
        assert_eq!(state.drain_phase, CellParticipantDrainPhase::Serving);
        assert!(state.takeover_registration_id.is_none());
        assert!(state.takeover_acknowledged_at.is_none());
        assert_eq!(
            state.degraded_reason,
            Some(CellParticipantDegradedReason::LeaseExpired)
        );
        assert_eq!(
            state.lease_source,
            CellParticipantLeaseSource::PublishedStateFallback
        );
        assert_eq!(state.lease.freshness, LeaseFreshness::Expired);
    }

    #[test]
    fn convergence_acknowledges_graceful_takeover_when_replacement_is_healthy() {
        let now = OffsetDateTime::now_utc();
        let draining_registration = LeaseRegistrationRecord::new(
            "controller:node-a",
            "runtime_process",
            "controller:node-a",
            "controller",
            Some(String::from("node-a")),
            15,
        )
        .with_readiness(LeaseReadiness::Ready)
        .with_drain_intent(LeaseDrainIntent::Draining);
        let replacement_registration = LeaseRegistrationRecord::new(
            "worker:node-b",
            "runtime_process",
            "worker:node-b",
            "worker",
            Some(String::from("node-b")),
            15,
        )
        .with_readiness(LeaseReadiness::Ready)
        .with_drain_intent(LeaseDrainIntent::Serving);
        let directory = CellDirectoryRecord::new(
            "local:local-cell",
            "local-cell",
            RegionDirectoryRecord::new("local", "local"),
        )
        .with_participant(
            CellParticipantRecord::new(
                "controller:node-a",
                "runtime_process",
                "controller:node-a",
                "controller",
            )
            .with_node_name("node-a")
            .with_service_groups(["control"])
            .with_lease_registration_id("controller:node-a"),
        )
        .with_participant(
            CellParticipantRecord::new(
                "worker:node-b",
                "runtime_process",
                "worker:node-b",
                "worker",
            )
            .with_node_name("node-b")
            .with_service_groups(["control"])
            .with_lease_registration_id("worker:node-b"),
        );

        let converged = converge_cell_directory_participants_at(
            &directory,
            [&draining_registration, &replacement_registration],
            now,
        );
        let draining_participant = converged
            .participants
            .iter()
            .find(|participant| participant.registration_id == "controller:node-a")
            .unwrap_or_else(|| panic!("missing draining participant"));
        let draining_state = draining_participant
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing draining participant state"));
        assert_eq!(draining_state.drain_intent, LeaseDrainIntent::Draining);
        assert_eq!(
            draining_state.published_drain_intent(),
            LeaseDrainIntent::Draining
        );
        assert_eq!(
            draining_state.drain_phase,
            CellParticipantDrainPhase::TakeoverAcknowledged
        );
        assert_eq!(
            draining_state.takeover_registration_id.as_deref(),
            Some("worker:node-b")
        );
        assert_eq!(draining_state.takeover_acknowledged_at, Some(now));
        assert!(draining_state.degraded_reason.is_none());

        let resolved = resolve_cell_service_group_directory(&converged);
        let control = resolved
            .groups
            .iter()
            .find(|entry| entry.group == "control")
            .unwrap_or_else(|| panic!("missing control service-group entry"));
        let draining_resolution = control
            .registrations
            .iter()
            .find(|registration| registration.registration_id == "controller:node-a")
            .unwrap_or_else(|| panic!("missing draining service-group registration"));
        assert_eq!(
            draining_resolution.drain_phase,
            Some(CellParticipantDrainPhase::TakeoverAcknowledged)
        );
        assert_eq!(
            draining_resolution.takeover_registration_id.as_deref(),
            Some("worker:node-b")
        );
        assert_eq!(draining_resolution.takeover_acknowledged_at, Some(now));
        assert!(!draining_resolution.healthy);
    }

    #[tokio::test]
    async fn local_cell_registry_publish_projects_local_participant_without_ownership() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let registry = LocalCellRegistry::open_local(
            state
                .checked_join("local-registry-state.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let state_store = MetadataCollection::<LocalCellRegistryState>::open_local(
            state
                .checked_join("local-registry-state.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store = CellDirectoryCollection::open_local(
            state
                .checked_join("cell-directory.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let registration_store = LeaseRegistrationCollection::open_local(
            state
                .checked_join("lease-registrations.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let registration = LeaseRegistrationRecord::new(
            "worker:node-a",
            "runtime_process",
            "worker:node-a",
            "worker",
            Some(String::from("node-a")),
            15,
        )
        .with_readiness(LeaseReadiness::Ready)
        .with_drain_intent(LeaseDrainIntent::Serving);
        let now = OffsetDateTime::now_utc();
        let participant = CellParticipantRecord::new(
            "worker:node-a",
            "runtime_process",
            "worker:node-a",
            "worker",
        )
        .with_node_name("node-a")
        .with_service_groups(["data_and_messaging"])
        .with_lease_registration_id("worker:node-a")
        .with_state(
            CellParticipantState::new(
                LeaseReadiness::Ready,
                LeaseDrainIntent::Serving,
                CellParticipantLeaseState::new(
                    registration.lease_renewed_at,
                    registration.lease_expires_at,
                    registration.lease_duration_seconds,
                    registration.lease_freshness_at(now),
                ),
            )
            .with_lease_source(CellParticipantLeaseSource::LinkedRegistration),
        );

        let directory = registry
            .publish(
                &cell_directory_store,
                &registration_store,
                &LocalCellRegistryPublication::new(
                    "local:cell-a",
                    "cell-a",
                    RegionDirectoryRecord::new("local", "local"),
                    registration.clone(),
                    participant,
                ),
                now,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(directory.cell_id, "local:cell-a");
        assert_eq!(directory.cell_name, "cell-a");
        assert_eq!(directory.participants.len(), 1);
        assert!(
            state_store
                .get("local:cell-a")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );
    }

    #[tokio::test]
    async fn local_cell_registry_owner_reconciles_replayed_peer_from_cached_leases() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let registry_path = state
            .checked_join("local-registry-state.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let registry = LocalCellRegistry::open_local(&registry_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let state_store = MetadataCollection::<LocalCellRegistryState>::open_local(&registry_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store = CellDirectoryCollection::open_local(
            state
                .checked_join("cell-directory.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let registration_store = LeaseRegistrationCollection::open_local(
            state
                .checked_join("lease-registrations.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let local_registration = registration_store
            .upsert(
                "controller:node-a",
                LeaseRegistrationRecord::new(
                    "controller:node-a",
                    "runtime_process",
                    "controller:node-a",
                    "controller",
                    Some(String::from("node-a")),
                    15,
                )
                .with_readiness(LeaseReadiness::Ready)
                .with_drain_intent(LeaseDrainIntent::Serving),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .value;
        let initial_observed_at = OffsetDateTime::now_utc();
        let local_participant = CellParticipantRecord::new(
            "controller:node-a",
            "runtime_process",
            "controller:node-a",
            "controller",
        )
        .with_node_name("node-a")
        .with_service_groups(["control"])
        .with_lease_registration_id("controller:node-a")
        .with_state(
            CellParticipantState::new(
                local_registration.readiness,
                local_registration.drain_intent,
                CellParticipantLeaseState::new(
                    local_registration.lease_renewed_at,
                    local_registration.lease_expires_at,
                    local_registration.lease_duration_seconds,
                    local_registration.lease_freshness_at(initial_observed_at),
                ),
            )
            .with_lease_source(CellParticipantLeaseSource::LinkedRegistration),
        );
        let peer_registration = {
            let mut registration = LeaseRegistrationRecord::new(
                "worker:node-b",
                "runtime_process",
                "worker:node-b",
                "worker",
                Some(String::from("node-b")),
                15,
            )
            .with_readiness(LeaseReadiness::Ready)
            .with_drain_intent(LeaseDrainIntent::Draining);
            registration.lease_renewed_at = initial_observed_at - Duration::seconds(45);
            registration.lease_expires_at = initial_observed_at - Duration::seconds(30);
            registration_store
                .upsert("worker:node-b", registration, None)
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .value
        };

        let initial_directory = registry
            .publish(
                &cell_directory_store,
                &registration_store,
                &LocalCellRegistryPublication::new(
                    "local:cell-a",
                    "cell-a",
                    RegionDirectoryRecord::new("local", "local"),
                    local_registration.clone(),
                    local_participant.clone(),
                )
                .with_directory_reconciliation_ownership(true),
                initial_observed_at,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(initial_directory.participants.len(), 1);

        let persisted_state = state_store
            .get("local:cell-a")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted local registry state"));
        assert!(persisted_state.value.lease_cursor.revision > 0);
        assert_eq!(
            persisted_state
                .value
                .active_registrations
                .get("worker:node-b"),
            Some(&peer_registration)
        );
        assert_eq!(persisted_state.value.cache_snapshots.len(), 1);
        let persisted_snapshot_key = local_cell_registry_cache_snapshot_key(
            persisted_state.value.lease_cursor,
            persisted_state.value.cell_directory_cursor,
        );
        let persisted_snapshot = persisted_state
            .value
            .cache_snapshots
            .get(persisted_snapshot_key.as_str())
            .unwrap_or_else(|| panic!("missing persisted cursor-keyed cache snapshot"));
        assert_eq!(
            persisted_snapshot.active_registrations.get("worker:node-b"),
            Some(&peer_registration)
        );

        let current_directory = cell_directory_store
            .get("local:cell-a")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing current cell directory"));
        let mut seeded_directory = current_directory.value.clone();
        let mut seeded_peer = CellParticipantRecord::new(
            "worker:node-b",
            "runtime_process",
            "worker:node-b",
            "worker",
        )
        .with_node_name("node-b")
        .with_service_groups(["data_and_messaging"])
        .with_lease_registration_id("worker:node-b")
        .with_state(CellParticipantState::new(
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            CellParticipantLeaseState::new(
                initial_observed_at - Duration::seconds(5),
                initial_observed_at + Duration::seconds(30),
                15,
                LeaseFreshness::Fresh,
            ),
        ))
        .with_reconciliation(CellParticipantReconciliationState::new(
            initial_observed_at - Duration::seconds(10),
        ));
        seeded_peer.registered_at = peer_registration.registered_at;
        seeded_directory.upsert_participant(seeded_peer);
        cell_directory_store
            .upsert(
                "local:cell-a",
                seeded_directory,
                Some(current_directory.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut trimmed_state = persisted_state.value.clone();
        trimmed_state.active_registrations.clear();
        state_store
            .upsert("local:cell-a", trimmed_state, Some(persisted_state.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let replay_observed_at = initial_observed_at + Duration::seconds(5);
        let reconciled_directory = registry
            .publish(
                &cell_directory_store,
                &registration_store,
                &LocalCellRegistryPublication::new(
                    "local:cell-a",
                    "cell-a",
                    RegionDirectoryRecord::new("local", "local"),
                    local_registration,
                    local_participant,
                )
                .with_directory_reconciliation_ownership(true),
                replay_observed_at,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let reconciled_peer = reconciled_directory
            .participants
            .iter()
            .find(|participant| participant.registration_id == "worker:node-b")
            .unwrap_or_else(|| panic!("missing reconciled peer participant"));
        let reconciled_peer_state = reconciled_peer
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing reconciled peer state"));
        assert_eq!(reconciled_peer_state.readiness, LeaseReadiness::Ready);
        assert_eq!(
            reconciled_peer_state.drain_intent,
            LeaseDrainIntent::Draining
        );
        assert_eq!(
            reconciled_peer_state.lease.freshness,
            LeaseFreshness::Expired
        );
        assert_eq!(
            reconciled_peer_state.lease_source,
            CellParticipantLeaseSource::LinkedRegistration
        );

        let replayed_state = state_store
            .get("local:cell-a")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing replayed local registry state"));
        assert!(
            replayed_state.value.cell_directory_cursor.revision
                > persisted_state.value.cell_directory_cursor.revision
        );
        assert_eq!(replayed_state.value.cache_snapshots.len(), 2);
        assert!(replayed_state.value.quarantined_registrations.is_empty());
    }

    #[tokio::test]
    async fn local_cell_registry_owner_recovers_from_compacted_source_cursors_using_snapshot_checkpoints()
     {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let registry_path = state
            .checked_join("local-registry-state.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let registry = LocalCellRegistry::open_local(&registry_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let state_store = MetadataCollection::<LocalCellRegistryState>::open_local(&registry_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store = CellDirectoryCollection::open_local(
            state
                .checked_join("cell-directory.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let registration_store = LeaseRegistrationCollection::open_local(
            state
                .checked_join("lease-registrations.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));

        let local_registration = registration_store
            .upsert(
                "controller:node-a",
                LeaseRegistrationRecord::new(
                    "controller:node-a",
                    "runtime_process",
                    "controller:node-a",
                    "controller",
                    Some(String::from("node-a")),
                    15,
                )
                .with_readiness(LeaseReadiness::Ready)
                .with_drain_intent(LeaseDrainIntent::Serving),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .value;
        let initial_observed_at = OffsetDateTime::now_utc();
        let local_participant = CellParticipantRecord::new(
            "controller:node-a",
            "runtime_process",
            "controller:node-a",
            "controller",
        )
        .with_node_name("node-a")
        .with_service_groups(["control"])
        .with_lease_registration_id("controller:node-a")
        .with_state(
            CellParticipantState::new(
                local_registration.readiness,
                local_registration.drain_intent,
                CellParticipantLeaseState::new(
                    local_registration.lease_renewed_at,
                    local_registration.lease_expires_at,
                    local_registration.lease_duration_seconds,
                    local_registration.lease_freshness_at(initial_observed_at),
                ),
            )
            .with_lease_source(CellParticipantLeaseSource::LinkedRegistration),
        );
        let peer_registration = {
            let mut registration = LeaseRegistrationRecord::new(
                "worker:node-b",
                "runtime_process",
                "worker:node-b",
                "worker",
                Some(String::from("node-b")),
                15,
            )
            .with_readiness(LeaseReadiness::Ready)
            .with_drain_intent(LeaseDrainIntent::Draining);
            registration.lease_renewed_at = initial_observed_at - Duration::seconds(45);
            registration.lease_expires_at = initial_observed_at - Duration::seconds(30);
            registration_store
                .upsert("worker:node-b", registration, None)
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .value
        };

        registry
            .publish(
                &cell_directory_store,
                &registration_store,
                &LocalCellRegistryPublication::new(
                    "local:cell-a",
                    "cell-a",
                    RegionDirectoryRecord::new("local", "local"),
                    local_registration.clone(),
                    local_participant.clone(),
                )
                .with_directory_reconciliation_ownership(true),
                initial_observed_at,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let persisted_state = state_store
            .get("local:cell-a")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted local registry state"));

        let current_directory = cell_directory_store
            .get("local:cell-a")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing current cell directory"));
        let seeded_directory = current_directory.value.clone();
        let mut seeded_peer = CellParticipantRecord::new(
            "worker:node-b",
            "runtime_process",
            "worker:node-b",
            "worker",
        )
        .with_node_name("node-b")
        .with_service_groups(["data_and_messaging"])
        .with_lease_registration_id("worker:node-b")
        .with_state(CellParticipantState::new(
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            CellParticipantLeaseState::new(
                initial_observed_at - Duration::seconds(5),
                initial_observed_at + Duration::seconds(30),
                15,
                LeaseFreshness::Fresh,
            ),
        ))
        .with_reconciliation(CellParticipantReconciliationState::new(
            initial_observed_at - Duration::seconds(10),
        ));
        seeded_peer.registered_at = peer_registration.registered_at;
        let mut latest_directory = cell_directory_store
            .upsert(
                "local:cell-a",
                seeded_directory.clone().with_participant(seeded_peer),
                Some(current_directory.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut latest_peer_registration = registration_store
            .get("worker:node-b")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing peer registration"));

        for _ in 0..300 {
            latest_directory = cell_directory_store
                .upsert(
                    "local:cell-a",
                    latest_directory.value.clone(),
                    Some(latest_directory.version),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            latest_peer_registration = registration_store
                .upsert(
                    "worker:node-b",
                    latest_peer_registration.value.clone(),
                    Some(latest_peer_registration.version),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let mut stale_state = persisted_state.value.clone();
        stale_state.active_registrations.clear();
        stale_state.cache_snapshots.clear();
        state_store
            .upsert("local:cell-a", stale_state, Some(persisted_state.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let replay_observed_at = initial_observed_at + Duration::seconds(5);
        let reconciled_directory = registry
            .publish(
                &cell_directory_store,
                &registration_store,
                &LocalCellRegistryPublication::new(
                    "local:cell-a",
                    "cell-a",
                    RegionDirectoryRecord::new("local", "local"),
                    local_registration,
                    local_participant,
                )
                .with_directory_reconciliation_ownership(true),
                replay_observed_at,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reconciled_peer = reconciled_directory
            .participants
            .iter()
            .find(|participant| participant.registration_id == "worker:node-b")
            .unwrap_or_else(|| panic!("missing reconciled peer participant"));
        let reconciled_peer_state = reconciled_peer
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing reconciled peer state"));
        assert_eq!(reconciled_peer_state.readiness, LeaseReadiness::Ready);
        assert_eq!(
            reconciled_peer_state.drain_intent,
            LeaseDrainIntent::Draining
        );
        assert_eq!(
            reconciled_peer_state.lease.freshness,
            LeaseFreshness::Expired
        );
        assert_eq!(
            reconciled_peer_state.lease_source,
            CellParticipantLeaseSource::LinkedRegistration
        );

        let replayed_state = state_store
            .get("local:cell-a")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing replayed local registry state"));
        assert!(
            replayed_state.value.lease_cursor.revision
                > persisted_state.value.lease_cursor.revision
        );
        assert!(
            replayed_state.value.cell_directory_cursor.revision
                > persisted_state.value.cell_directory_cursor.revision
        );
        assert_eq!(
            replayed_state
                .value
                .active_registrations
                .get("worker:node-b"),
            Some(&latest_peer_registration.value)
        );
        assert_eq!(replayed_state.value.cache_snapshots.len(), 1);
        assert!(replayed_state.value.quarantined_registrations.is_empty());
    }

    #[tokio::test]
    async fn local_cell_registry_owner_quarantines_conflicting_runtime_registrations_in_state() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let registry_path = state
            .checked_join("local-registry-state.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let registry = LocalCellRegistry::open_local(&registry_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let state_store = MetadataCollection::<LocalCellRegistryState>::open_local(&registry_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store = CellDirectoryCollection::open_local(
            state
                .checked_join("cell-directory.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let registration_store = LeaseRegistrationCollection::open_local(
            state
                .checked_join("lease-registrations.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let observed_at = OffsetDateTime::now_utc();
        let runtime_service_groups = [
            "control",
            "data_and_messaging",
            "edge",
            "governance_and_operations",
            "identity_and_policy",
            "uvm",
        ];

        let local_registration = registration_store
            .upsert(
                "all_in_one:node-a",
                LeaseRegistrationRecord::new(
                    "all_in_one:node-a",
                    "runtime_process",
                    "all_in_one:node-a",
                    "all_in_one",
                    Some(String::from("node-a")),
                    15,
                )
                .with_readiness(LeaseReadiness::Ready)
                .with_drain_intent(LeaseDrainIntent::Serving),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .value;
        let peer_registration = registration_store
            .upsert(
                "all_in_one:node-b",
                LeaseRegistrationRecord::new(
                    "all_in_one:node-b",
                    "runtime_process",
                    "all_in_one:node-b",
                    "all_in_one",
                    Some(String::from("node-b")),
                    15,
                )
                .with_readiness(LeaseReadiness::Ready)
                .with_drain_intent(LeaseDrainIntent::Serving),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .value;

        let mut peer_participant = build_runtime_participant(
            "all_in_one:node-b",
            "all_in_one",
            "node-b",
            runtime_service_groups,
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            LeaseFreshness::Fresh,
            observed_at,
        );
        peer_participant.registered_at = peer_registration.registered_at;
        cell_directory_store
            .upsert(
                "local:local-cell",
                CellDirectoryRecord::new(
                    "local:local-cell",
                    "local-cell",
                    RegionDirectoryRecord::new("local", "local"),
                )
                .with_participant(peer_participant),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut local_participant = build_runtime_participant(
            "all_in_one:node-a",
            "all_in_one",
            "node-a",
            runtime_service_groups,
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            LeaseFreshness::Fresh,
            observed_at,
        );
        local_participant.registered_at = local_registration.registered_at;
        let directory = registry
            .publish(
                &cell_directory_store,
                &registration_store,
                &LocalCellRegistryPublication::new(
                    "local:local-cell",
                    "local-cell",
                    RegionDirectoryRecord::new("local", "local"),
                    local_registration,
                    local_participant,
                )
                .with_directory_reconciliation_ownership(true),
                observed_at,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let persisted_state = state_store
            .get("local:local-cell")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted local registry state"));
        assert!(persisted_state.value.active_registrations.is_empty());
        assert_eq!(
            persisted_state
                .value
                .quarantined_registrations
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                String::from("all_in_one:node-a"),
                String::from("all_in_one:node-b")
            ]
        );
        assert_eq!(persisted_state.value.cache_snapshots.len(), 1);
        let persisted_snapshot = persisted_state
            .value
            .cache_snapshots
            .values()
            .next()
            .unwrap_or_else(|| panic!("missing persisted cache snapshot"));
        assert!(persisted_snapshot.active_registrations.is_empty());
        assert_eq!(
            persisted_snapshot
                .quarantined_registrations
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec![
                String::from("all_in_one:node-a"),
                String::from("all_in_one:node-b")
            ]
        );

        let resolved = resolve_cell_service_group_directory(&directory);
        let edge = resolved
            .groups
            .iter()
            .find(|entry| entry.group == "edge")
            .unwrap_or_else(|| panic!("missing edge service-group entry"));
        assert_eq!(
            edge.conflict_state,
            CellServiceGroupConflictState::MultipleHealthyRegistrations
        );
        assert!(edge.resolved_registration_ids.is_empty());
    }

    #[tokio::test]
    async fn local_cell_registry_owner_quarantines_impossible_runtime_registration_links_before_merge()
     {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let registry_path = state
            .checked_join("local-registry-state.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let registry = LocalCellRegistry::open_local(&registry_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let state_store = MetadataCollection::<LocalCellRegistryState>::open_local(&registry_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store = CellDirectoryCollection::open_local(
            state
                .checked_join("cell-directory.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let registration_store = LeaseRegistrationCollection::open_local(
            state
                .checked_join("lease-registrations.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let observed_at = OffsetDateTime::now_utc();

        let local_registration = registration_store
            .upsert(
                "controller:node-a",
                LeaseRegistrationRecord::new(
                    "controller:node-a",
                    "runtime_process",
                    "controller:node-a",
                    "controller",
                    Some(String::from("node-a")),
                    15,
                )
                .with_readiness(LeaseReadiness::Ready)
                .with_drain_intent(LeaseDrainIntent::Serving),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .value;
        let peer_registration = registration_store
            .upsert(
                "worker:node-b",
                LeaseRegistrationRecord::new(
                    "worker:node-b",
                    "runtime_process",
                    "worker:node-b",
                    "worker",
                    Some(String::from("node-b")),
                    15,
                )
                .with_readiness(LeaseReadiness::Ready)
                .with_drain_intent(LeaseDrainIntent::Serving),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .value;

        let stale_peer = build_runtime_participant(
            "controller:node-b",
            "controller",
            "node-b",
            ["data_and_messaging"],
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            LeaseFreshness::Fresh,
            observed_at,
        )
        .with_lease_registration_id("worker:node-b");
        cell_directory_store
            .upsert(
                "local:local-cell",
                CellDirectoryRecord::new(
                    "local:local-cell",
                    "local-cell",
                    RegionDirectoryRecord::new("local", "local"),
                )
                .with_participant(stale_peer),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut local_participant = build_runtime_participant(
            "controller:node-a",
            "controller",
            "node-a",
            ["control"],
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            LeaseFreshness::Fresh,
            observed_at,
        );
        local_participant.registered_at = local_registration.registered_at;
        let directory = registry
            .publish(
                &cell_directory_store,
                &registration_store,
                &LocalCellRegistryPublication::new(
                    "local:local-cell",
                    "local-cell",
                    RegionDirectoryRecord::new("local", "local"),
                    local_registration,
                    local_participant,
                )
                .with_directory_reconciliation_ownership(true),
                observed_at,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let persisted_state = state_store
            .get("local:local-cell")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted local registry state"));
        assert_eq!(
            persisted_state
                .value
                .active_registrations
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec![String::from("controller:node-a")]
        );
        assert_eq!(
            persisted_state
                .value
                .quarantined_registrations
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec![String::from("worker:node-b")]
        );
        assert_eq!(
            persisted_state
                .value
                .quarantined_registrations
                .get("worker:node-b"),
            Some(&peer_registration)
        );

        let quarantined_peer = directory
            .participants
            .iter()
            .find(|participant| participant.registration_id == "controller:node-b")
            .unwrap_or_else(|| panic!("missing quarantined stale peer"));
        assert_eq!(quarantined_peer.subject_id, "controller:node-b");
        assert_eq!(quarantined_peer.role, "controller");
        assert_eq!(
            quarantined_peer.lease_registration_id.as_deref(),
            Some("worker:node-b")
        );
        let quarantined_peer_state = quarantined_peer
            .state
            .as_ref()
            .unwrap_or_else(|| panic!("missing quarantined stale peer state"));
        assert_eq!(
            quarantined_peer_state.drain_intent,
            LeaseDrainIntent::Draining
        );
        assert_eq!(
            quarantined_peer_state.lease.freshness,
            LeaseFreshness::Expired
        );
        assert_eq!(
            quarantined_peer_state.lease_source,
            CellParticipantLeaseSource::PublishedStateFallback
        );

        let resolved = resolve_cell_service_group_directory(&directory);
        let data = resolved
            .groups
            .iter()
            .find(|entry| entry.group == "data_and_messaging")
            .unwrap_or_else(|| panic!("missing data_and_messaging service-group entry"));
        assert_eq!(
            data.conflict_state,
            CellServiceGroupConflictState::NoConflict
        );
        assert!(data.resolved_registration_ids.is_empty());
        let quarantined_registration = data
            .registrations
            .iter()
            .find(|registration| registration.registration_id == "controller:node-b")
            .unwrap_or_else(|| panic!("missing quarantined data-and-messaging registration"));
        assert_eq!(quarantined_registration.subject_id, "controller:node-b");
        assert!(!quarantined_registration.healthy);
    }

    #[tokio::test]
    async fn local_cell_registry_publish_with_service_records_syncs_instances_and_scoped_endpoints()
    {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let registry = LocalCellRegistry::open_local(
            state
                .checked_join("local-registry-state.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store = CellDirectoryCollection::open_local(
            state
                .checked_join("cell-directory.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let registration_store = LeaseRegistrationCollection::open_local(
            state
                .checked_join("lease-registrations.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let service_instance_store = ServiceInstanceCollection::open(
            state
                .checked_join("service-instances.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let service_endpoint_store = ServiceEndpointCollection::open(
            state
                .checked_join("service-endpoints.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let observed_at = OffsetDateTime::now_utc();

        let peer_registration = LeaseRegistrationRecord::new(
            "worker:node-b",
            "runtime_process",
            "worker:node-b",
            "worker",
            Some(String::from("node-b")),
            15,
        )
        .with_readiness(LeaseReadiness::Ready)
        .with_drain_intent(LeaseDrainIntent::Serving);
        let mut peer_participant = build_runtime_participant(
            "worker:node-b",
            "worker",
            "node-b",
            ["data_and_messaging"],
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            LeaseFreshness::Fresh,
            observed_at,
        );
        peer_participant.registered_at = peer_registration.registered_at;
        cell_directory_store
            .upsert(
                "local:cell-a",
                CellDirectoryRecord::new(
                    "local:cell-a",
                    "cell-a",
                    RegionDirectoryRecord::new("local", "local"),
                )
                .with_participant(peer_participant.clone()),
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let peer_seed_instance = ServiceInstanceRecord::from_participant(
            "local:cell-a",
            "data_and_messaging",
            1,
            &peer_participant,
        );
        let peer_endpoint = ServiceEndpointRecord::from_service_instance(
            &peer_seed_instance,
            "127.0.0.1:7000",
            ServiceEndpointProtocol::Grpc,
        );
        service_endpoint_store
            .create(
                peer_endpoint.service_endpoint_id.as_str(),
                peer_endpoint.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stale_local_endpoint = ServiceEndpointRecord::from_service_instance(
            &ServiceInstanceRecord::new(
                "control:controller:node-a",
                "local:cell-a",
                "control",
                "controller:node-a",
                1,
            )
            .with_linked_lease_ids(["controller:node-a"]),
            "127.0.0.1:7443",
            ServiceEndpointProtocol::Https,
        );
        service_endpoint_store
            .create(
                stale_local_endpoint.service_endpoint_id.as_str(),
                stale_local_endpoint.clone(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let local_registration = LeaseRegistrationRecord::new(
            "controller:node-a",
            "runtime_process",
            "controller:node-a",
            "controller",
            Some(String::from("node-a")),
            15,
        )
        .with_readiness(LeaseReadiness::Ready)
        .with_drain_intent(LeaseDrainIntent::Serving);
        let mut local_participant = build_runtime_participant(
            "controller:node-a",
            "controller",
            "node-a",
            ["control", "edge"],
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            LeaseFreshness::Fresh,
            observed_at,
        );
        local_participant.registered_at = local_registration.registered_at;

        let directory = registry
            .publish_with_service_records(
                &cell_directory_store,
                &registration_store,
                &service_instance_store,
                &service_endpoint_store,
                &LocalCellRegistryPublication::new(
                    "local:cell-a",
                    "cell-a",
                    RegionDirectoryRecord::new("local", "local"),
                    local_registration,
                    local_participant,
                )
                .with_service_endpoint_bindings([
                    ServiceEndpointBinding::new(
                        "control",
                        "127.0.0.1:8443",
                        ServiceEndpointProtocol::Https,
                    ),
                    ServiceEndpointBinding::new(
                        "edge",
                        "127.0.0.1:9443",
                        ServiceEndpointProtocol::Grpc,
                    ),
                ]),
                observed_at,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(directory.participants.len(), 2);
        let persisted_directory = cell_directory_store
            .get("local:cell-a")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted cell directory"));
        let revision = persisted_directory.version;

        let active_instance_ids = service_instance_store
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .filter_map(|(key, stored)| (!stored.deleted).then_some(key))
            .collect::<Vec<_>>();
        assert_eq!(
            active_instance_ids,
            vec![
                String::from("control:controller:node-a"),
                String::from("data_and_messaging:worker:node-b"),
                String::from("edge:controller:node-a"),
            ]
        );

        let control_instance = service_instance_store
            .get("control:controller:node-a")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing control service instance"));
        assert!(!control_instance.deleted);
        assert_eq!(control_instance.value.cell_id, "local:cell-a");
        assert_eq!(control_instance.value.revision, revision);
        assert_eq!(
            control_instance.value.readiness,
            Some(LeaseReadiness::Ready)
        );
        assert_eq!(
            control_instance.value.drain_intent,
            Some(LeaseDrainIntent::Serving)
        );
        assert_eq!(
            control_instance.value.linked_lease_ids,
            vec![String::from("controller:node-a")]
        );

        let peer_instance = service_instance_store
            .get("data_and_messaging:worker:node-b")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing peer service instance"));
        assert!(!peer_instance.deleted);
        assert_eq!(peer_instance.value.revision, revision);
        assert_eq!(peer_instance.value.node_name.as_deref(), Some("node-b"));

        let control_endpoint = service_endpoint_store
            .get("control:controller:node-a:https:127.0.0.1:8443")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing control endpoint"));
        assert!(!control_endpoint.deleted);
        assert_eq!(control_endpoint.value.address, "127.0.0.1:8443");
        assert_eq!(
            control_endpoint.value.protocol,
            ServiceEndpointProtocol::Https
        );
        assert_eq!(control_endpoint.value.revision, revision);
        assert_eq!(
            control_endpoint.value.linked_lease_ids,
            vec![String::from("controller:node-a")]
        );

        let edge_endpoint = service_endpoint_store
            .get("edge:controller:node-a:grpc:127.0.0.1:9443")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing edge endpoint"));
        assert!(!edge_endpoint.deleted);
        assert_eq!(edge_endpoint.value.protocol, ServiceEndpointProtocol::Grpc);
        assert_eq!(edge_endpoint.value.revision, revision);

        let deleted_local_endpoint = service_endpoint_store
            .get(stale_local_endpoint.service_endpoint_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stale local endpoint tombstone"));
        assert!(deleted_local_endpoint.deleted);

        let preserved_peer_endpoint = service_endpoint_store
            .get(peer_endpoint.service_endpoint_id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing peer endpoint"));
        assert!(!preserved_peer_endpoint.deleted);
        assert_eq!(preserved_peer_endpoint.value.address, "127.0.0.1:7000");
    }

    #[tokio::test]
    async fn local_cell_registry_publish_with_service_records_rejects_unknown_endpoint_binding() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let registry = LocalCellRegistry::open_local(
            state
                .checked_join("local-registry-state.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let cell_directory_store = CellDirectoryCollection::open_local(
            state
                .checked_join("cell-directory.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let registration_store = LeaseRegistrationCollection::open_local(
            state
                .checked_join("lease-registrations.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let service_instance_store = ServiceInstanceCollection::open(
            state
                .checked_join("service-instances.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let service_endpoint_store = ServiceEndpointCollection::open(
            state
                .checked_join("service-endpoints.json")
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let observed_at = OffsetDateTime::now_utc();

        let local_registration = LeaseRegistrationRecord::new(
            "controller:node-a",
            "runtime_process",
            "controller:node-a",
            "controller",
            Some(String::from("node-a")),
            15,
        )
        .with_readiness(LeaseReadiness::Ready)
        .with_drain_intent(LeaseDrainIntent::Serving);
        let mut local_participant = build_runtime_participant(
            "controller:node-a",
            "controller",
            "node-a",
            ["control"],
            LeaseReadiness::Ready,
            LeaseDrainIntent::Serving,
            LeaseFreshness::Fresh,
            observed_at,
        );
        local_participant.registered_at = local_registration.registered_at;

        let error = registry
            .publish_with_service_records(
                &cell_directory_store,
                &registration_store,
                &service_instance_store,
                &service_endpoint_store,
                &LocalCellRegistryPublication::new(
                    "local:cell-a",
                    "cell-a",
                    RegionDirectoryRecord::new("local", "local"),
                    local_registration,
                    local_participant,
                )
                .with_service_endpoint_bindings([ServiceEndpointBinding::new(
                    "edge",
                    "127.0.0.1:8443",
                    ServiceEndpointProtocol::Https,
                )]),
                observed_at,
            )
            .await
            .expect_err("unknown service-group binding should be rejected");

        assert!(
            error
                .to_string()
                .contains("does not match any projected service instance")
        );
        assert!(
            cell_directory_store
                .get("local:cell-a")
                .await
                .unwrap_or_else(|fetch_error| panic!("{fetch_error}"))
                .is_none()
        );
        assert!(
            service_instance_store
                .list()
                .await
                .unwrap_or_else(|fetch_error| panic!("{fetch_error}"))
                .is_empty()
        );
        assert!(
            service_endpoint_store
                .list()
                .await
                .unwrap_or_else(|fetch_error| panic!("{fetch_error}"))
                .is_empty()
        );
    }

    #[tokio::test]
    async fn service_group_discovery_projector_builds_cross_cell_and_region_cache() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let source_path = state
            .checked_join("service-group-directory.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let discovery_path = state
            .checked_join("service-group-discovery.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let projector_path = state
            .checked_join("service-group-discovery-state.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let source = CellServiceGroupDirectoryCollection::open_local(&source_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let discovery_store = ServiceGroupDiscoveryCollection::open(&discovery_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let projector = ServiceGroupDiscoveryProjector::open_local(&projector_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let projector_state_store =
            MetadataCollection::<ServiceGroupDiscoveryState>::open_local(&projector_path)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let observed_at = OffsetDateTime::now_utc();

        let east_directory = build_cell_service_group_directory(
            "us-east-1:cell-a",
            "cell-a",
            "us-east-1",
            "US East 1",
            vec![
                build_runtime_participant(
                    "controller:use1-a",
                    "controller",
                    "use1-a",
                    ["control"],
                    LeaseReadiness::Ready,
                    LeaseDrainIntent::Serving,
                    LeaseFreshness::Fresh,
                    observed_at,
                ),
                build_runtime_participant(
                    "edge:use1-a",
                    "edge",
                    "use1-edge-a",
                    ["edge"],
                    LeaseReadiness::Ready,
                    LeaseDrainIntent::Serving,
                    LeaseFreshness::Fresh,
                    observed_at,
                ),
            ],
        );
        let west_directory = build_cell_service_group_directory(
            "us-west-2:cell-b",
            "cell-b",
            "us-west-2",
            "US West 2",
            vec![build_runtime_participant(
                "controller:usw2-b",
                "controller",
                "usw2-b",
                ["control"],
                LeaseReadiness::Ready,
                LeaseDrainIntent::Serving,
                LeaseFreshness::Fresh,
                observed_at,
            )],
        );

        let east_cell_id = east_directory.cell_id.clone();
        source
            .create(east_cell_id.as_str(), east_directory)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let west_cell_id = west_directory.cell_id.clone();
        source
            .create(west_cell_id.as_str(), west_directory)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let projections = projector
            .refresh(&source, &discovery_store)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(projections.len(), 2);

        let control = discovery_store
            .get("control")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing control discovery projection"));
        assert!(!control.deleted);
        assert_eq!(
            control.value.healthy_regions,
            vec![String::from("us-east-1"), String::from("us-west-2")]
        );
        assert_eq!(
            control.value.healthy_cells,
            vec![
                String::from("us-east-1:cell-a"),
                String::from("us-west-2:cell-b")
            ]
        );
        assert_eq!(control.value.regions.len(), 2);

        let edge = discovery_store
            .get("edge")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing edge discovery projection"));
        assert!(!edge.deleted);
        assert_eq!(edge.value.healthy_regions, vec![String::from("us-east-1")]);
        assert_eq!(
            edge.value.healthy_cells,
            vec![String::from("us-east-1:cell-a")]
        );
        assert_eq!(edge.value.regions.len(), 1);

        let persisted_state = projector_state_store
            .get(super::SERVICE_GROUP_DISCOVERY_STATE_KEY)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted service-group discovery state"));
        assert!(
            persisted_state
                .value
                .service_group_directory_cursor
                .revision
                > 0
        );
        assert_eq!(persisted_state.value.cached_cells.len(), 2);
    }

    #[tokio::test]
    async fn service_group_discovery_projector_soft_deletes_removed_groups() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let source_path = state
            .checked_join("service-group-directory.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let discovery_path = state
            .checked_join("service-group-discovery.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let projector_path = state
            .checked_join("service-group-discovery-state.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let source = CellServiceGroupDirectoryCollection::open_local(&source_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let discovery_store = ServiceGroupDiscoveryCollection::open(&discovery_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let projector = ServiceGroupDiscoveryProjector::open_local(&projector_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let projector_state_store =
            MetadataCollection::<ServiceGroupDiscoveryState>::open_local(&projector_path)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let observed_at = OffsetDateTime::now_utc();

        let source_directory = build_cell_service_group_directory(
            "local:cell-a",
            "cell-a",
            "local",
            "local",
            vec![build_runtime_participant(
                "edge:local-a",
                "edge",
                "local-a",
                ["edge"],
                LeaseReadiness::Ready,
                LeaseDrainIntent::Serving,
                LeaseFreshness::Fresh,
                observed_at,
            )],
        );

        let source_cell_id = source_directory.cell_id.clone();
        let stored_source = source
            .create(source_cell_id.as_str(), source_directory)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        projector
            .refresh(&source, &discovery_store)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let initial_edge = discovery_store
            .get("edge")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing initial edge discovery projection"));
        assert!(!initial_edge.deleted);

        source
            .soft_delete("local:cell-a", Some(stored_source.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let projections = projector
            .refresh(&source, &discovery_store)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(projections.is_empty());
        let deleted_edge = discovery_store
            .get("edge")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing deleted edge discovery projection"));
        assert!(deleted_edge.deleted);

        let persisted_state = projector_state_store
            .get(super::SERVICE_GROUP_DISCOVERY_STATE_KEY)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted service-group discovery state"));
        assert!(persisted_state.value.cached_cells.is_empty());
        assert!(
            persisted_state
                .value
                .service_group_directory_cursor
                .revision
                > 0
        );
    }

    #[tokio::test]
    async fn service_group_discovery_projector_recovers_from_compacted_source_cursor_using_snapshot_checkpoint()
     {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let source_path = state
            .checked_join("service-group-directory.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let discovery_path = state
            .checked_join("service-group-discovery.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let projector_path = state
            .checked_join("service-group-discovery-state.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let source = CellServiceGroupDirectoryCollection::open_local(&source_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let discovery_store = ServiceGroupDiscoveryCollection::open(&discovery_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let projector = ServiceGroupDiscoveryProjector::open_local(&projector_path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let projector_state_store =
            MetadataCollection::<ServiceGroupDiscoveryState>::open_local(&projector_path)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let observed_at = OffsetDateTime::now_utc();

        let source_cell_id = String::from("us-east-1:cell-a");
        let mut stored_directory = source
            .create(
                source_cell_id.as_str(),
                build_cell_service_group_directory(
                    source_cell_id.as_str(),
                    "cell-a",
                    "us-east-1",
                    "US East 1",
                    vec![build_runtime_participant(
                        "edge:use1-a",
                        "edge",
                        "use1-edge-a",
                        ["edge"],
                        LeaseReadiness::Ready,
                        LeaseDrainIntent::Serving,
                        LeaseFreshness::Fresh,
                        observed_at,
                    )],
                ),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        projector
            .refresh(&source, &discovery_store)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let persisted_state = projector_state_store
            .get(super::SERVICE_GROUP_DISCOVERY_STATE_KEY)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted service-group discovery state"));

        for iteration in 0..300 {
            let service_group = if iteration == 299 { "control" } else { "edge" };
            stored_directory = source
                .upsert(
                    source_cell_id.as_str(),
                    build_cell_service_group_directory(
                        source_cell_id.as_str(),
                        "cell-a",
                        "us-east-1",
                        "US East 1",
                        vec![build_runtime_participant(
                            "svc:use1-a",
                            service_group,
                            "use1-a",
                            [service_group],
                            LeaseReadiness::Ready,
                            LeaseDrainIntent::Serving,
                            LeaseFreshness::Fresh,
                            observed_at + Duration::seconds(iteration as i64 + 1),
                        )],
                    ),
                    Some(stored_directory.version),
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        }

        let mut stale_state = persisted_state.value.clone();
        stale_state.cached_cells.clear();
        projector_state_store
            .upsert(
                super::SERVICE_GROUP_DISCOVERY_STATE_KEY,
                stale_state,
                Some(persisted_state.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let projections = projector
            .refresh(&source, &discovery_store)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(projections.len(), 1);
        assert_eq!(projections[0].group, "control");

        let control = discovery_store
            .get("control")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing control discovery projection"));
        assert!(!control.deleted);
        assert_eq!(
            control.value.healthy_regions,
            vec![String::from("us-east-1")]
        );

        let deleted_edge = discovery_store
            .get("edge")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing deleted edge projection"));
        assert!(deleted_edge.deleted);

        let replayed_state = projector_state_store
            .get(super::SERVICE_GROUP_DISCOVERY_STATE_KEY)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing replayed service-group discovery state"));
        assert!(
            replayed_state.value.service_group_directory_cursor.revision
                > persisted_state
                    .value
                    .service_group_directory_cursor
                    .revision
        );
        assert_eq!(replayed_state.value.cached_cells.len(), 1);
        let cached_directory = replayed_state
            .value
            .cached_cells
            .get(source_cell_id.as_str())
            .unwrap_or_else(|| panic!("missing cached source cell"));
        assert_eq!(cached_directory.groups.len(), 1);
        assert_eq!(cached_directory.groups[0].group, "control");
    }

    #[test]
    fn cell_home_projection_records_capture_full_lineage() {
        let east_home = CellHomeLocation::new(
            "global:cell-a",
            "cell-a",
            RegionDirectoryRecord::new("us-east", "US East"),
        );
        let west_home = CellHomeLocation::new(
            "global:cell-b",
            "cell-b",
            RegionDirectoryRecord::new("us-west", "US West"),
        );

        let tenant = CellHomeProjectionRecord::tenant("tnt_aaaaaaaaaaaaaaaaaaaa", east_home);
        let project = CellHomeProjectionRecord::project(
            "tnt_aaaaaaaaaaaaaaaaaaaa",
            "prj_aaaaaaaaaaaaaaaaaaaa",
            west_home.clone(),
        );
        let workload = CellHomeProjectionRecord::workload(
            "tnt_aaaaaaaaaaaaaaaaaaaa",
            "prj_aaaaaaaaaaaaaaaaaaaa",
            "wrk_aaaaaaaaaaaaaaaaaaaa",
            west_home.clone(),
        );
        let deployment = CellHomeProjectionRecord::deployment(
            "tnt_aaaaaaaaaaaaaaaaaaaa",
            "prj_aaaaaaaaaaaaaaaaaaaa",
            "wrk_aaaaaaaaaaaaaaaaaaaa",
            "dep_aaaaaaaaaaaaaaaaaaaa",
            west_home.clone(),
        );
        let mut service_shard = CellHomeProjectionRecord::service_shard(
            "tnt_aaaaaaaaaaaaaaaaaaaa",
            "prj_aaaaaaaaaaaaaaaaaaaa",
            "wrk_aaaaaaaaaaaaaaaaaaaa",
            "dep_aaaaaaaaaaaaaaaaaaaa",
            "shd_api_0001",
            west_home.clone(),
        );

        assert_eq!(tenant.subject_kind, CellHomeSubjectKind::Tenant);
        assert_eq!(tenant.subject_id, "tnt_aaaaaaaaaaaaaaaaaaaa");
        assert_eq!(
            tenant.lineage.tenant_id.as_deref(),
            Some("tnt_aaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            tenant.key(),
            cell_home_projection_key(CellHomeSubjectKind::Tenant, "tnt_aaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(project.subject_kind, CellHomeSubjectKind::Project);
        assert_eq!(
            project.lineage.project_id.as_deref(),
            Some("prj_aaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            workload.lineage.workload_id.as_deref(),
            Some("wrk_aaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            deployment.lineage.deployment_id.as_deref(),
            Some("dep_aaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            service_shard.lineage.service_shard_id.as_deref(),
            Some("shd_api_0001")
        );

        service_shard.set_home(CellHomeLocation::new(
            "global:cell-c",
            "cell-c",
            RegionDirectoryRecord::new("eu-central", "EU Central"),
        ));
        assert_eq!(service_shard.home.cell_id, "global:cell-c");
        assert_eq!(service_shard.home.region.region_id, "eu-central");
        assert!(service_shard.updated_at >= service_shard.registered_at);
    }

    #[tokio::test]
    async fn local_cell_home_projection_collection_persists_and_replays_changes() {
        let state = TempState::new().unwrap_or_else(|error| panic!("{error}"));
        let path = state
            .checked_join("cell-homes.json")
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_a = CellHomeProjectionCollection::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_b = CellHomeProjectionCollection::open(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let initial_cursor = collection_a
            .current_cursor()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let east_home = CellHomeLocation::new(
            "global:cell-a",
            "cell-a",
            RegionDirectoryRecord::new("us-east", "US East"),
        );
        let west_home = CellHomeLocation::new(
            "global:cell-b",
            "cell-b",
            RegionDirectoryRecord::new("us-west", "US West"),
        );

        let tenant = CellHomeProjectionRecord::tenant("tnt_aaaaaaaaaaaaaaaaaaaa", east_home);
        let deployment = CellHomeProjectionRecord::deployment(
            "tnt_aaaaaaaaaaaaaaaaaaaa",
            "prj_aaaaaaaaaaaaaaaaaaaa",
            "wrk_aaaaaaaaaaaaaaaaaaaa",
            "dep_aaaaaaaaaaaaaaaaaaaa",
            west_home.clone(),
        );

        let created_tenant = collection_a
            .create(tenant.key().as_str(), tenant)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_deployment = collection_a
            .create(deployment.key().as_str(), deployment)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let loaded_deployment = collection_b
            .get(created_deployment.value.key().as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing persisted deployment home"));
        assert_eq!(loaded_deployment.version, created_deployment.version);
        assert_eq!(loaded_deployment.value.home.cell_id, "global:cell-b");
        assert_eq!(
            loaded_deployment.value.lineage.workload_id.as_deref(),
            Some("wrk_aaaaaaaaaaaaaaaaaaaa")
        );

        let first_page = collection_b
            .changes_since(Some(initial_cursor), 10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first_page.changes.len(), 2);
        assert_eq!(first_page.changes[0].key, created_tenant.value.key());
        assert_eq!(first_page.changes[1].key, created_deployment.value.key());

        let mut updated_deployment = loaded_deployment.value.clone();
        updated_deployment.set_home(CellHomeLocation::new(
            "global:cell-c",
            "cell-c",
            RegionDirectoryRecord::new("eu-central", "EU Central"),
        ));
        collection_a
            .upsert(
                updated_deployment.key().as_str(),
                updated_deployment,
                Some(loaded_deployment.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        collection_a
            .soft_delete(
                created_tenant.value.key().as_str(),
                Some(created_tenant.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let second_page = collection_b
            .changes_since(Some(first_page.next_cursor), 10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second_page.changes.len(), 2);
        assert_eq!(
            second_page.changes[0].document.value.home.cell_id,
            "global:cell-c"
        );
        assert_eq!(
            second_page.changes[0].document.value.home.region.region_id,
            "eu-central"
        );
        assert!(second_page.changes[1].document.deleted);
        assert_eq!(second_page.changes[1].key, created_tenant.value.key());
    }
}
