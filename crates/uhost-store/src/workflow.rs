//! Shared durable workflow collection abstractions.
//!
//! Phase 1 keeps the all-in-one adapter file-backed via
//! [`DocumentStore<T>`](crate::document::DocumentStore) while introducing a
//! reusable workflow envelope for long-running operations. Services can persist
//! workflow instances, step progression, and optimistic-concurrency-protected
//! updates without binding directly to one concrete adapter shape.

use std::fmt;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use uhost_core::{ErrorCode, PlatformError, Result, sha256_hex};

use crate::document::{DocumentStore, StoredDocument};

/// Boxed future returned by workflow backends.
pub type WorkflowResultFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// High-level lifecycle phase of a durable workflow instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowPhase {
    /// Workflow exists but has not begun executing steps.
    Pending,
    /// Workflow is actively progressing.
    Running,
    /// Workflow is intentionally paused.
    Paused,
    /// Workflow finished successfully.
    Completed,
    /// Workflow failed and needs repair or operator action.
    Failed,
    /// Workflow was compensated or rolled back.
    RolledBack,
}

/// Durable state of one workflow step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStepState {
    /// Step has not started.
    Pending,
    /// Step is the current active step.
    Active,
    /// Step finished successfully.
    Completed,
    /// Step failed.
    Failed,
    /// Step was rolled back or skipped by compensation.
    RolledBack,
}

/// Persisted state of one step effect journal entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStepEffectState {
    /// The effect intent was journaled but not yet confirmed complete.
    Pending,
    /// The effect completed and its recorded result may be replayed safely.
    Completed,
}

/// One durable effect journal entry attached to a workflow step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowStepEffect {
    /// Stable effect name within the step (`apply_restore`, `emit_outbox`, etc.).
    pub effect_kind: String,
    /// Idempotency key that downstream effect handlers must reuse on retries.
    pub idempotency_key: String,
    /// Current persisted journal state for this effect.
    pub state: WorkflowStepEffectState,
    /// Optional human-readable detail describing the recorded effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Optional stable digest or token representing the recorded effect result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<String>,
    /// Timestamp when the effect intent was first journaled.
    pub recorded_at: OffsetDateTime,
    /// Timestamp when the effect was durably marked complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<OffsetDateTime>,
}

/// Action the caller should take after consulting one step effect journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowStepEffectExecution {
    /// Execute the effect and later persist completion using this journal entry.
    Execute(WorkflowStepEffect),
    /// Reuse the already recorded result and skip re-executing the effect.
    Replay(WorkflowStepEffect),
}

impl WorkflowStepEffectExecution {
    /// Return the journal entry backing this decision.
    pub fn effect(&self) -> &WorkflowStepEffect {
        match self {
            Self::Execute(effect) | Self::Replay(effect) => effect,
        }
    }

    /// Consume the decision and return the journal entry backing it.
    pub fn into_effect(self) -> WorkflowStepEffect {
        match self {
            Self::Execute(effect) | Self::Replay(effect) => effect,
        }
    }
}

/// Crash-window idempotency ledger entry for one workflow step effect.
///
/// This record is keyed by the effect idempotency key and is intended to be
/// committed atomically with the durable side effect result. Retries can consult
/// it when the effect already ran but the workflow step has not yet persisted
/// `complete_effect(...)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowEffectLedgerRecord {
    /// Stable workflow identifier that owns the effect.
    pub workflow_id: String,
    /// Workflow family (`ha.failover`, `storage.volume_restore`, etc.).
    pub workflow_kind: String,
    /// Subject resource kind represented by this workflow.
    pub subject_kind: String,
    /// Subject resource identifier represented by this workflow.
    pub subject_id: String,
    /// Step index that owns the journaled effect.
    pub step_index: usize,
    /// Stable human-readable step name.
    pub step_name: String,
    /// Stable effect name within the step.
    pub effect_kind: String,
    /// Idempotency key the side effect must reuse on retries.
    pub idempotency_key: String,
    /// Stable digest or token representing the recorded side effect result.
    pub result_digest: String,
    /// Optional human-readable detail copied from the effect journal entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Timestamp when this ledger entry was durably recorded.
    pub recorded_at: OffsetDateTime,
}

impl WorkflowEffectLedgerRecord {
    /// Return the document key that should store this ledger entry.
    pub fn key(&self) -> &str {
        self.idempotency_key.as_str()
    }
}

/// One durable workflow step record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// Stable human-readable step name.
    pub name: String,
    /// Monotonic step index within the workflow definition.
    pub index: usize,
    /// Current persisted step state.
    pub state: WorkflowStepState,
    /// Optional operator or controller detail associated with the last step mutation.
    pub detail: Option<String>,
    /// Per-step effect journal entries and their reusable idempotency keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effect_journal: Vec<WorkflowStepEffect>,
    /// Last successful persistence timestamp for this step.
    pub updated_at: OffsetDateTime,
}

impl WorkflowStep {
    /// Create a new pending step.
    pub fn new(name: impl Into<String>, index: usize) -> Self {
        Self {
            name: name.into(),
            index,
            state: WorkflowStepState::Pending,
            detail: None,
            effect_journal: Vec::new(),
            updated_at: OffsetDateTime::now_utc(),
        }
    }

    /// Persist a new step state and optional detail.
    pub fn transition(&mut self, state: WorkflowStepState, detail: Option<String>) {
        self.state = state;
        self.detail = detail;
        self.updated_at = OffsetDateTime::now_utc();
    }

    /// Return the most recently journaled effect entry for the supplied effect kind.
    pub fn effect(&self, effect_kind: &str) -> Option<&WorkflowStepEffect> {
        let effect_kind = effect_kind.trim();
        if effect_kind.is_empty() {
            return None;
        }
        self.effect_journal
            .iter()
            .rev()
            .find(|effect| effect.effect_kind == effect_kind)
    }

    /// Journal one effect intent, reusing prior idempotency state when present.
    pub fn begin_effect(
        &mut self,
        effect_kind: impl AsRef<str>,
        idempotency_key: impl AsRef<str>,
        detail: Option<String>,
    ) -> Result<WorkflowStepEffectExecution> {
        self.begin_effect_at(
            effect_kind,
            idempotency_key,
            detail,
            OffsetDateTime::now_utc(),
        )
    }

    /// Journal one effect intent at an explicit timestamp.
    pub fn begin_effect_at(
        &mut self,
        effect_kind: impl AsRef<str>,
        idempotency_key: impl AsRef<str>,
        detail: Option<String>,
        observed_at: OffsetDateTime,
    ) -> Result<WorkflowStepEffectExecution> {
        let effect_kind = normalize_workflow_step_effect_kind(effect_kind.as_ref())?.to_owned();
        // Effect replay is keyed by effect kind. A pending journal entry means
        // the caller should continue executing that in-flight effect; a
        // completed entry means the caller should replay the durable result
        // instead of overwriting the earlier idempotency lineage.
        if let Some(existing) = self
            .effect_journal
            .iter()
            .rev()
            .find(|effect| effect.effect_kind == effect_kind)
            .cloned()
        {
            return Ok(match existing.state {
                WorkflowStepEffectState::Pending => WorkflowStepEffectExecution::Execute(existing),
                WorkflowStepEffectState::Completed => WorkflowStepEffectExecution::Replay(existing),
            });
        }

        let idempotency_key =
            normalize_workflow_step_effect_idempotency_key(idempotency_key.as_ref())?.to_owned();
        let effect = WorkflowStepEffect {
            effect_kind,
            idempotency_key,
            state: WorkflowStepEffectState::Pending,
            detail,
            result_digest: None,
            recorded_at: observed_at,
            completed_at: None,
        };
        self.effect_journal.push(effect.clone());
        self.updated_at = observed_at;
        Ok(WorkflowStepEffectExecution::Execute(effect))
    }

    /// Mark one journaled effect as completed.
    pub fn complete_effect(
        &mut self,
        effect_kind: impl AsRef<str>,
        result_digest: Option<&str>,
        detail: Option<String>,
    ) -> Result<WorkflowStepEffect> {
        self.complete_effect_at(
            effect_kind,
            result_digest,
            detail,
            OffsetDateTime::now_utc(),
        )
    }

    /// Mark one journaled effect as completed at an explicit timestamp.
    pub fn complete_effect_at(
        &mut self,
        effect_kind: impl AsRef<str>,
        result_digest: Option<&str>,
        detail: Option<String>,
        observed_at: OffsetDateTime,
    ) -> Result<WorkflowStepEffect> {
        let effect_kind = normalize_workflow_step_effect_kind(effect_kind.as_ref())?;
        let result_digest = result_digest
            .map(|value| normalize_workflow_step_effect_result_digest(value).map(str::to_owned))
            .transpose()?;
        let step_name = self.name.clone();

        let effect = self
            .effect_journal
            .iter_mut()
            .rev()
            .find(|effect| effect.effect_kind == effect_kind)
            .ok_or_else(|| {
                PlatformError::conflict(format!(
                    "workflow step `{}` has no effect journal entry for `{effect_kind}`",
                    step_name
                ))
            })?;
        if effect.state == WorkflowStepEffectState::Completed {
            if let Some(result_digest) = result_digest.as_deref()
                && effect.result_digest.as_deref() != Some(result_digest)
            {
                return Err(PlatformError::conflict(format!(
                    "workflow step effect `{effect_kind}` already completed with a different result digest"
                )));
            }
            return Ok(effect.clone());
        }

        effect.state = WorkflowStepEffectState::Completed;
        if let Some(detail) = detail {
            effect.detail = Some(detail);
        }
        if let Some(result_digest) = result_digest {
            effect.result_digest = Some(result_digest);
        }
        effect.completed_at = Some(observed_at);
        self.updated_at = observed_at;
        Ok(effect.clone())
    }
}

fn normalize_workflow_step_effect_kind(effect_kind: &str) -> Result<&str> {
    let trimmed = effect_kind.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(
            "workflow step effect_kind may not be empty",
        ));
    }
    Ok(trimmed)
}

fn normalize_workflow_step_effect_idempotency_key(idempotency_key: &str) -> Result<&str> {
    let trimmed = idempotency_key.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(
            "workflow step effect idempotency_key may not be empty",
        ));
    }
    Ok(trimmed)
}

fn normalize_workflow_step_effect_result_digest(result_digest: &str) -> Result<&str> {
    let trimmed = result_digest.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(
            "workflow step effect result_digest may not be empty",
        ));
    }
    Ok(trimmed)
}

/// Lease-backed runner claim for one workflow instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowRunnerClaim {
    /// Stable workflow runner identifier.
    pub runner_id: String,
    /// Timestamp when this runner most recently acquired the claim.
    pub claimed_at: OffsetDateTime,
    /// Timestamp of the most recent successful runner heartbeat.
    pub last_heartbeat_at: OffsetDateTime,
    /// Timestamp when the claim expires unless heartbeated again.
    pub lease_expires_at: OffsetDateTime,
    /// Fencing token that must accompany heartbeats and updates.
    pub fencing_token: String,
    /// Number of durable takeovers performed for this workflow.
    #[serde(default)]
    pub takeover_count: u64,
}

impl WorkflowRunnerClaim {
    fn new(
        workflow_id: &str,
        runner_id: String,
        claimed_at: OffsetDateTime,
        lease_duration: Duration,
        takeover_count: u64,
    ) -> Self {
        Self {
            runner_id: runner_id.clone(),
            claimed_at,
            last_heartbeat_at: claimed_at,
            lease_expires_at: claimed_at + lease_duration,
            fencing_token: sha256_hex(
                format!("{workflow_id}:{runner_id}:{takeover_count}:{claimed_at}").as_bytes(),
            ),
            takeover_count,
        }
    }

    /// Whether the runner claim remains live at the supplied time.
    pub fn is_active_at(&self, now: OffsetDateTime) -> bool {
        self.lease_expires_at > now
    }
}

/// Durable workflow envelope storing generic progression metadata plus domain state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowInstance<T> {
    /// Stable workflow identifier.
    pub id: String,
    /// Workflow family (`lifecycle.rollout`, `ha.failover`, etc.).
    pub workflow_kind: String,
    /// Domain resource kind represented by this workflow.
    pub subject_kind: String,
    /// Domain resource identifier represented by this workflow.
    pub subject_id: String,
    /// Current workflow phase.
    pub phase: WorkflowPhase,
    /// Current active step index when one is active or most recently completed.
    pub current_step_index: Option<usize>,
    /// Persisted workflow steps.
    pub steps: Vec<WorkflowStep>,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Last workflow mutation timestamp.
    pub updated_at: OffsetDateTime,
    /// Completion timestamp for terminal phases.
    pub completed_at: Option<OffsetDateTime>,
    /// Earliest timestamp when the next controller attempt should run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<OffsetDateTime>,
    /// Active runner claim for this workflow when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_claim: Option<WorkflowRunnerClaim>,
    /// Domain-specific state carried by the workflow.
    pub state: T,
}

impl<T> WorkflowInstance<T> {
    /// Create a new pending workflow instance.
    pub fn new(
        id: impl Into<String>,
        workflow_kind: impl Into<String>,
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        state: T,
        steps: Vec<WorkflowStep>,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: id.into(),
            workflow_kind: workflow_kind.into(),
            subject_kind: subject_kind.into(),
            subject_id: subject_id.into(),
            phase: WorkflowPhase::Pending,
            current_step_index: None,
            steps,
            created_at: now,
            updated_at: now,
            completed_at: None,
            next_attempt_at: None,
            runner_claim: None,
            state,
        }
    }

    /// Mark the workflow as updated.
    pub fn touch(&mut self) {
        self.touch_at(OffsetDateTime::now_utc());
    }

    /// Mark the workflow as updated at an explicit timestamp.
    pub fn touch_at(&mut self, updated_at: OffsetDateTime) {
        self.updated_at = updated_at;
    }

    /// Persist a new high-level workflow phase.
    pub fn set_phase(&mut self, phase: WorkflowPhase) {
        self.set_phase_at(phase, OffsetDateTime::now_utc());
    }

    /// Persist a new high-level workflow phase at an explicit timestamp.
    pub fn set_phase_at(&mut self, phase: WorkflowPhase, observed_at: OffsetDateTime) {
        self.phase = phase;
        self.updated_at = observed_at;
        if matches!(
            self.phase,
            WorkflowPhase::Completed | WorkflowPhase::Failed | WorkflowPhase::RolledBack
        ) {
            self.completed_at = Some(self.updated_at);
            self.next_attempt_at = None;
            if let Some(claim) = self.runner_claim.as_mut() {
                claim.last_heartbeat_at = observed_at;
                claim.lease_expires_at = observed_at;
            }
        }
    }

    /// Return one step by index.
    pub fn step(&self, index: usize) -> Option<&WorkflowStep> {
        self.steps.iter().find(|step| step.index == index)
    }

    /// Return one mutable step by index.
    pub fn step_mut(&mut self, index: usize) -> Option<&mut WorkflowStep> {
        self.steps.iter_mut().find(|step| step.index == index)
    }

    /// Whether the workflow is due for another controller attempt.
    pub fn is_due_at(&self, now: OffsetDateTime) -> bool {
        match self.next_attempt_at {
            Some(next_attempt_at) => next_attempt_at <= now,
            None => true,
        }
    }

    /// Set or clear the next controller attempt timestamp.
    pub fn set_next_attempt_at(
        &mut self,
        next_attempt_at: Option<OffsetDateTime>,
        observed_at: OffsetDateTime,
    ) {
        self.next_attempt_at = next_attempt_at;
        self.updated_at = observed_at;
    }

    /// Return whether a live runner claim currently exists.
    pub fn has_active_runner_claim_at(&self, now: OffsetDateTime) -> bool {
        self.runner_claim
            .as_ref()
            .is_some_and(|claim| claim.is_active_at(now))
    }

    /// Verify the supplied runner and fencing token still own this workflow.
    pub fn assert_runner_fence_at(
        &self,
        runner_id: &str,
        fencing_token: &str,
        observed_at: OffsetDateTime,
    ) -> Result<()> {
        let runner_id = normalize_runner_id(runner_id)?;
        let claim = self
            .runner_claim
            .as_ref()
            .ok_or_else(|| PlatformError::conflict("workflow has no active runner claim"))?;
        if claim.runner_id != runner_id {
            return Err(PlatformError::conflict(format!(
                "workflow runner claim held by {}",
                claim.runner_id
            )));
        }
        if claim.fencing_token != fencing_token {
            return Err(PlatformError::conflict(
                "workflow runner fencing token does not match",
            ));
        }
        if !claim.is_active_at(observed_at) {
            return Err(PlatformError::conflict(
                "workflow runner claim expired; acquire a fenced takeover before mutating",
            ));
        }
        Ok(())
    }

    /// Acquire or renew a workflow runner claim, taking over only after expiry.
    pub fn claim_runner_at(
        &mut self,
        runner_id: &str,
        lease_duration: Duration,
        observed_at: OffsetDateTime,
    ) -> Result<&WorkflowRunnerClaim> {
        let runner_id = normalize_runner_id(runner_id)?;
        let lease_duration = normalize_runner_lease_duration(lease_duration)?;
        // Claim semantics are intentionally simple: the same runner renews in
        // place, a different runner can only take over after expiry, and every
        // takeover increments the fencing lineage to invalidate stale actors.
        if let Some(existing) = self.runner_claim.as_ref()
            && existing.runner_id != runner_id
            && existing.is_active_at(observed_at)
        {
            return Err(PlatformError::conflict(format!(
                "workflow runner claim held by {} until {}",
                existing.runner_id, existing.lease_expires_at
            )));
        }

        let workflow_id = self.id.clone();
        let next_claim = match self.runner_claim.as_ref() {
            Some(existing)
                if existing.runner_id == runner_id && existing.is_active_at(observed_at) =>
            {
                let mut renewed = existing.clone();
                renewed.last_heartbeat_at = observed_at;
                renewed.lease_expires_at = observed_at + lease_duration;
                renewed
            }
            Some(existing) => WorkflowRunnerClaim::new(
                workflow_id.as_str(),
                runner_id.to_owned(),
                observed_at,
                lease_duration,
                existing.takeover_count.saturating_add(1),
            ),
            None => WorkflowRunnerClaim::new(
                workflow_id.as_str(),
                runner_id.to_owned(),
                observed_at,
                lease_duration,
                0,
            ),
        };
        self.runner_claim = Some(next_claim);
        self.updated_at = observed_at;
        self.runner_claim
            .as_ref()
            .ok_or_else(|| PlatformError::conflict("workflow runner claim missing after acquire"))
    }

    /// Heartbeat an existing workflow runner claim without changing ownership.
    pub fn heartbeat_runner_at(
        &mut self,
        runner_id: &str,
        fencing_token: &str,
        lease_duration: Duration,
        observed_at: OffsetDateTime,
    ) -> Result<&WorkflowRunnerClaim> {
        self.assert_runner_fence_at(runner_id, fencing_token, observed_at)?;
        let lease_duration = normalize_runner_lease_duration(lease_duration)?;
        let claim = self
            .runner_claim
            .as_mut()
            .ok_or_else(|| PlatformError::conflict("workflow has no active runner claim"))?;
        claim.last_heartbeat_at = observed_at;
        claim.lease_expires_at = observed_at + lease_duration;
        self.updated_at = observed_at;
        Ok(claim)
    }

    /// Clear a workflow runner claim only when the fencing token still matches.
    pub fn release_runner_claim_at(
        &mut self,
        runner_id: &str,
        fencing_token: &str,
        observed_at: OffsetDateTime,
    ) -> Result<()> {
        self.assert_runner_fence_at(runner_id, fencing_token, observed_at)?;
        self.runner_claim = None;
        self.updated_at = observed_at;
        Ok(())
    }
}

impl WorkflowEffectLedgerRecord {
    /// Build one ledger record from a previously journaled workflow step effect.
    pub fn from_workflow_effect<T>(
        workflow: &WorkflowInstance<T>,
        step_index: usize,
        effect_kind: impl AsRef<str>,
        result_digest: impl AsRef<str>,
    ) -> Result<Self> {
        Self::from_workflow_effect_at(
            workflow,
            step_index,
            effect_kind,
            result_digest,
            OffsetDateTime::now_utc(),
        )
    }

    /// Build one ledger record from a journaled workflow step effect at an
    /// explicit timestamp.
    pub fn from_workflow_effect_at<T>(
        workflow: &WorkflowInstance<T>,
        step_index: usize,
        effect_kind: impl AsRef<str>,
        result_digest: impl AsRef<str>,
        recorded_at: OffsetDateTime,
    ) -> Result<Self> {
        let effect_kind = normalize_workflow_step_effect_kind(effect_kind.as_ref())?.to_owned();
        let result_digest =
            normalize_workflow_step_effect_result_digest(result_digest.as_ref())?.to_owned();
        let step = workflow.step(step_index).ok_or_else(|| {
            PlatformError::conflict(format!(
                "workflow `{}` has no step `{step_index}`",
                workflow.id
            ))
        })?;
        let effect = step.effect(effect_kind.as_str()).ok_or_else(|| {
            PlatformError::conflict(format!(
                "workflow step `{}` has no effect journal entry for `{effect_kind}`",
                step.name
            ))
        })?;

        Ok(Self {
            workflow_id: workflow.id.clone(),
            workflow_kind: workflow.workflow_kind.clone(),
            subject_kind: workflow.subject_kind.clone(),
            subject_id: workflow.subject_id.clone(),
            step_index,
            step_name: step.name.clone(),
            effect_kind,
            idempotency_key: effect.idempotency_key.clone(),
            result_digest,
            detail: effect.detail.clone(),
            recorded_at,
        })
    }

    /// Verify that this ledger entry still belongs to the supplied workflow
    /// effect.
    pub fn validate_for_workflow<T>(&self, workflow: &WorkflowInstance<T>) -> Result<()> {
        let expected_effect_kind =
            normalize_workflow_step_effect_kind(self.effect_kind.as_str())?.to_owned();
        let expected_idempotency_key =
            normalize_workflow_step_effect_idempotency_key(self.idempotency_key.as_str())?
                .to_owned();
        let expected_result_digest =
            normalize_workflow_step_effect_result_digest(self.result_digest.as_str())?.to_owned();
        let step = workflow.step(self.step_index).ok_or_else(|| {
            PlatformError::conflict(format!(
                "workflow `{}` has no step `{}`",
                workflow.id, self.step_index
            ))
        })?;
        let effect = step.effect(expected_effect_kind.as_str()).ok_or_else(|| {
            PlatformError::conflict(format!(
                "workflow step `{}` has no effect journal entry for `{}`",
                step.name, self.effect_kind
            ))
        })?;

        if self.workflow_id != workflow.id
            || self.workflow_kind != workflow.workflow_kind
            || self.subject_kind != workflow.subject_kind
            || self.subject_id != workflow.subject_id
            || self.step_name != step.name
            || effect.idempotency_key != expected_idempotency_key
            || self.result_digest != expected_result_digest
        {
            return Err(PlatformError::conflict(
                "workflow effect ledger entry belongs to a different workflow effect",
            ));
        }

        Ok(())
    }
}

fn normalize_runner_id(runner_id: &str) -> Result<&str> {
    let trimmed = runner_id.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(
            "workflow runner_id may not be empty",
        ));
    }
    Ok(trimmed)
}

fn normalize_runner_lease_duration(lease_duration: Duration) -> Result<Duration> {
    if lease_duration <= Duration::ZERO {
        return Err(PlatformError::invalid(
            "workflow runner lease duration must be positive",
        ));
    }
    Ok(lease_duration)
}

/// Shared trait for durable workflow persistence.
pub trait WorkflowStore<T>: Send + Sync + 'static
where
    T: Clone + Send + Sync + 'static,
{
    /// List all workflow records, including soft-deleted entries.
    fn list(&self) -> WorkflowResultFuture<'_, Vec<(String, StoredDocument<WorkflowInstance<T>>)>>;

    /// Fetch one workflow record by key.
    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> WorkflowResultFuture<'a, Option<StoredDocument<WorkflowInstance<T>>>>;

    /// Create a new workflow record. Fails when the key already exists.
    fn create<'a>(
        &'a self,
        key: &'a str,
        value: WorkflowInstance<T>,
    ) -> WorkflowResultFuture<'a, StoredDocument<WorkflowInstance<T>>>;

    /// Create or update a workflow record with optimistic concurrency semantics.
    fn upsert<'a>(
        &'a self,
        key: &'a str,
        value: WorkflowInstance<T>,
        expected_version: Option<u64>,
    ) -> WorkflowResultFuture<'a, StoredDocument<WorkflowInstance<T>>>;

    /// Soft-delete a workflow record with optional optimistic concurrency checking.
    fn soft_delete<'a>(
        &'a self,
        key: &'a str,
        expected_version: Option<u64>,
    ) -> WorkflowResultFuture<'a, ()>;
}

impl<T> WorkflowStore<T> for DocumentStore<WorkflowInstance<T>>
where
    T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
{
    fn list(&self) -> WorkflowResultFuture<'_, Vec<(String, StoredDocument<WorkflowInstance<T>>)>> {
        Box::pin(async move { DocumentStore::list(self).await })
    }

    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> WorkflowResultFuture<'a, Option<StoredDocument<WorkflowInstance<T>>>> {
        Box::pin(async move { DocumentStore::get(self, key).await })
    }

    fn create<'a>(
        &'a self,
        key: &'a str,
        value: WorkflowInstance<T>,
    ) -> WorkflowResultFuture<'a, StoredDocument<WorkflowInstance<T>>> {
        Box::pin(async move { DocumentStore::create(self, key, value).await })
    }

    fn upsert<'a>(
        &'a self,
        key: &'a str,
        value: WorkflowInstance<T>,
        expected_version: Option<u64>,
    ) -> WorkflowResultFuture<'a, StoredDocument<WorkflowInstance<T>>> {
        Box::pin(async move { DocumentStore::upsert(self, key, value, expected_version).await })
    }

    fn soft_delete<'a>(
        &'a self,
        key: &'a str,
        expected_version: Option<u64>,
    ) -> WorkflowResultFuture<'a, ()> {
        Box::pin(async move { DocumentStore::soft_delete(self, key, expected_version).await })
    }
}

/// Cloneable handle to a workflow backend.
#[derive(Clone)]
pub struct WorkflowCollection<T>
where
    T: Clone + Send + Sync + 'static,
{
    inner: Arc<dyn WorkflowStore<T>>,
}

impl<T> WorkflowCollection<T>
where
    T: Clone + Send + Sync + 'static,
{
    /// Wrap a workflow backend behind the shared service-facing boundary.
    pub fn from_backend(backend: impl WorkflowStore<T>) -> Self {
        Self {
            inner: Arc::new(backend),
        }
    }

    /// List all workflow records, including soft-deleted entries.
    pub async fn list(&self) -> Result<Vec<(String, StoredDocument<WorkflowInstance<T>>)>> {
        self.inner.list().await
    }

    /// Fetch one workflow record by key.
    pub async fn get(&self, key: &str) -> Result<Option<StoredDocument<WorkflowInstance<T>>>> {
        self.inner.get(key).await
    }

    /// Create a new workflow record. Fails when the key already exists.
    pub async fn create(
        &self,
        key: &str,
        value: WorkflowInstance<T>,
    ) -> Result<StoredDocument<WorkflowInstance<T>>> {
        self.inner.create(key, value).await
    }

    /// Create or update a workflow record with optimistic concurrency semantics.
    pub async fn upsert(
        &self,
        key: &str,
        value: WorkflowInstance<T>,
        expected_version: Option<u64>,
    ) -> Result<StoredDocument<WorkflowInstance<T>>> {
        self.inner.upsert(key, value, expected_version).await
    }

    /// Soft-delete a workflow record with optional optimistic concurrency checking.
    pub async fn soft_delete(&self, key: &str, expected_version: Option<u64>) -> Result<()> {
        self.inner.soft_delete(key, expected_version).await
    }
}

impl<T> WorkflowCollection<T>
where
    T: Clone + DeserializeOwned + Serialize + Send + Sync + 'static,
{
    /// Open the default file-backed workflow backend for all-in-one mode.
    pub async fn open_local(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self::from_backend(DocumentStore::open(path).await?))
    }

    /// Read-modify-write one workflow with optimistic concurrency retries.
    pub async fn mutate<F>(
        &self,
        key: &str,
        mut mutate: F,
    ) -> Result<StoredDocument<WorkflowInstance<T>>>
    where
        F: FnMut(&mut WorkflowInstance<T>) -> Result<()>,
    {
        self.mutate_with_output(key, |workflow| {
            mutate(workflow)?;
            Ok(())
        })
        .await
        .map(|(stored, ())| stored)
    }

    /// Read-modify-write one workflow with optimistic concurrency retries and
    /// return a derived output from the successful mutation.
    pub async fn mutate_with_output<F, O>(
        &self,
        key: &str,
        mut mutate: F,
    ) -> Result<(StoredDocument<WorkflowInstance<T>>, O)>
    where
        F: FnMut(&mut WorkflowInstance<T>) -> Result<O>,
    {
        loop {
            let stored = self.get(key).await?.ok_or_else(|| {
                PlatformError::not_found(format!("workflow `{key}` does not exist"))
            })?;
            let version = stored.version;
            let mut workflow = stored.value;
            let output = mutate(&mut workflow)?;
            match self.upsert(key, workflow, Some(version)).await {
                Ok(updated) => return Ok((updated, output)),
                Err(error) if error.code == ErrorCode::Conflict => continue,
                Err(error) => return Err(error),
            }
        }
    }

    /// Begin one journaled effect for a workflow step and return the durable
    /// workflow update plus the execution decision.
    pub async fn begin_step_effect(
        &self,
        key: &str,
        step_index: usize,
        effect_kind: &str,
        idempotency_key: &str,
        detail: Option<String>,
    ) -> Result<(
        StoredDocument<WorkflowInstance<T>>,
        WorkflowStepEffectExecution,
    )> {
        self.begin_step_effect_at(
            key,
            step_index,
            effect_kind,
            idempotency_key,
            detail,
            OffsetDateTime::now_utc(),
        )
        .await
    }

    /// Begin one journaled effect for a workflow step at an explicit
    /// timestamp.
    pub async fn begin_step_effect_at(
        &self,
        key: &str,
        step_index: usize,
        effect_kind: &str,
        idempotency_key: &str,
        detail: Option<String>,
        observed_at: OffsetDateTime,
    ) -> Result<(
        StoredDocument<WorkflowInstance<T>>,
        WorkflowStepEffectExecution,
    )> {
        self.mutate_with_output(key, |workflow| {
            let workflow_id = workflow.id.clone();
            let step = workflow.step_mut(step_index).ok_or_else(|| {
                PlatformError::conflict(format!(
                    "workflow `{}` has no step `{step_index}`",
                    workflow_id
                ))
            })?;
            step.begin_effect_at(effect_kind, idempotency_key, detail.clone(), observed_at)
        })
        .await
    }

    /// Mark one journaled workflow step effect as completed and return the
    /// durable workflow update plus the completed effect.
    pub async fn complete_step_effect(
        &self,
        key: &str,
        step_index: usize,
        effect_kind: &str,
        result_digest: Option<&str>,
        detail: Option<String>,
    ) -> Result<(StoredDocument<WorkflowInstance<T>>, WorkflowStepEffect)> {
        self.complete_step_effect_at(
            key,
            step_index,
            effect_kind,
            result_digest,
            detail,
            OffsetDateTime::now_utc(),
        )
        .await
    }

    /// Mark one journaled workflow step effect as completed at an explicit
    /// timestamp.
    pub async fn complete_step_effect_at(
        &self,
        key: &str,
        step_index: usize,
        effect_kind: &str,
        result_digest: Option<&str>,
        detail: Option<String>,
        observed_at: OffsetDateTime,
    ) -> Result<(StoredDocument<WorkflowInstance<T>>, WorkflowStepEffect)> {
        self.mutate_with_output(key, |workflow| {
            let workflow_id = workflow.id.clone();
            let step = workflow.step_mut(step_index).ok_or_else(|| {
                PlatformError::conflict(format!(
                    "workflow `{}` has no step `{step_index}`",
                    workflow_id
                ))
            })?;
            step.complete_effect_at(effect_kind, result_digest, detail.clone(), observed_at)
        })
        .await
    }

    /// Acquire or renew a workflow runner claim durably.
    pub async fn claim_runner_at(
        &self,
        key: &str,
        runner_id: &str,
        lease_duration: Duration,
        observed_at: OffsetDateTime,
    ) -> Result<StoredDocument<WorkflowInstance<T>>> {
        self.mutate(key, |workflow| {
            workflow.claim_runner_at(runner_id, lease_duration, observed_at)?;
            Ok(())
        })
        .await
    }

    /// Heartbeat one workflow runner claim durably.
    pub async fn heartbeat_runner_at(
        &self,
        key: &str,
        runner_id: &str,
        fencing_token: &str,
        lease_duration: Duration,
        observed_at: OffsetDateTime,
    ) -> Result<StoredDocument<WorkflowInstance<T>>> {
        self.mutate(key, |workflow| {
            workflow.heartbeat_runner_at(runner_id, fencing_token, lease_duration, observed_at)?;
            Ok(())
        })
        .await
    }

    /// Release one workflow runner claim durably.
    pub async fn release_runner_claim_at(
        &self,
        key: &str,
        runner_id: &str,
        fencing_token: &str,
        observed_at: OffsetDateTime,
    ) -> Result<StoredDocument<WorkflowInstance<T>>> {
        self.mutate(key, |workflow| {
            workflow.release_runner_claim_at(runner_id, fencing_token, observed_at)?;
            Ok(())
        })
        .await
    }
}

impl<T> fmt::Debug for WorkflowCollection<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowCollection")
            .field("backend", &"dyn WorkflowStore")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use tempfile::tempdir;
    use time::{Duration, OffsetDateTime};

    use uhost_core::ErrorCode;

    use super::{
        WorkflowCollection, WorkflowEffectLedgerRecord, WorkflowInstance, WorkflowPhase,
        WorkflowStep, WorkflowStepEffectExecution, WorkflowStepEffectState, WorkflowStepState,
    };

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ExampleState {
        phase: String,
    }

    fn example_workflow() -> WorkflowInstance<ExampleState> {
        WorkflowInstance::new(
            "wf-1",
            "example.workflow",
            "example_resource",
            "res-1",
            ExampleState {
                phase: String::from("planned"),
            },
            vec![
                WorkflowStep::new("validate", 0),
                WorkflowStep::new("apply", 1),
            ],
        )
    }

    #[tokio::test]
    async fn local_workflow_collection_round_trips_instances() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let collection =
            WorkflowCollection::<ExampleState>::open_local(temp.path().join("workflow.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));

        collection
            .create("wf-1", example_workflow())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let loaded = collection
            .get("wf-1")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing workflow"));
        assert_eq!(loaded.value.workflow_kind, "example.workflow");
        assert_eq!(loaded.value.phase, WorkflowPhase::Pending);
        assert_eq!(loaded.value.steps.len(), 2);
        assert_eq!(loaded.value.steps[0].state, WorkflowStepState::Pending);
    }

    #[tokio::test]
    async fn local_workflow_collection_preserves_cross_handle_version_checks() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = temp.path().join("workflow.json");
        let collection_a = WorkflowCollection::<ExampleState>::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let collection_b = WorkflowCollection::<ExampleState>::open_local(&path)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let created = collection_a
            .create("wf-1", example_workflow())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let mut updated = created.value.clone();
        updated.set_phase(WorkflowPhase::Running);
        updated.current_step_index = Some(0);
        let step = updated
            .step_mut(0)
            .unwrap_or_else(|| panic!("missing first step"));
        step.transition(WorkflowStepState::Active, Some(String::from("started")));

        let stored = collection_b
            .upsert("wf-1", updated.clone(), Some(created.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(stored.version, created.version + 1);
        assert_eq!(stored.value.phase, WorkflowPhase::Running);

        let stale = collection_a
            .upsert("wf-1", updated, Some(created.version))
            .await
            .expect_err("stale version should fail");
        assert_eq!(stale.code, ErrorCode::Conflict);
    }

    #[test]
    fn workflow_step_effect_journal_reuses_pending_and_completed_entries() {
        let mut step = WorkflowStep::new("apply", 1);
        let journaled_at = OffsetDateTime::UNIX_EPOCH + Duration::seconds(40);
        let execution = step
            .begin_effect_at(
                "apply_restore",
                "idem-1",
                Some(String::from("prepared restore apply")),
                journaled_at,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let pending = match execution {
            WorkflowStepEffectExecution::Execute(effect) => effect,
            WorkflowStepEffectExecution::Replay(_) => panic!("first effect should execute"),
        };
        assert_eq!(pending.effect_kind, "apply_restore");
        assert_eq!(pending.idempotency_key, "idem-1");
        assert_eq!(pending.state, WorkflowStepEffectState::Pending);
        assert_eq!(step.effect_journal.len(), 1);

        let retry_execution = step
            .begin_effect_at(
                "apply_restore",
                "idem-2",
                Some(String::from("should reuse first key")),
                journaled_at + Duration::seconds(5),
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let retry_effect = match retry_execution {
            WorkflowStepEffectExecution::Execute(effect) => effect,
            WorkflowStepEffectExecution::Replay(_) => {
                panic!("pending effect retry should keep executing")
            }
        };
        assert_eq!(retry_effect.idempotency_key, "idem-1");
        assert_eq!(step.effect_journal.len(), 1);

        let completed = step
            .complete_effect_at(
                "apply_restore",
                Some("digest-1"),
                Some(String::from("restore apply recorded")),
                journaled_at + Duration::seconds(10),
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(completed.state, WorkflowStepEffectState::Completed);
        assert_eq!(completed.result_digest.as_deref(), Some("digest-1"));
        assert_eq!(
            completed.completed_at,
            Some(journaled_at + Duration::seconds(10))
        );

        let replay = step
            .begin_effect_at(
                "apply_restore",
                "idem-3",
                Some(String::from("should not be used")),
                journaled_at + Duration::seconds(20),
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let replay_effect = match replay {
            WorkflowStepEffectExecution::Replay(effect) => effect,
            WorkflowStepEffectExecution::Execute(_) => {
                panic!("completed effect should replay recorded result")
            }
        };
        assert_eq!(replay_effect.idempotency_key, "idem-1");
        assert_eq!(replay_effect.result_digest.as_deref(), Some("digest-1"));
        assert_eq!(step.effect_journal.len(), 1);
    }

    #[tokio::test]
    async fn local_workflow_collection_persists_step_effect_journals() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let collection =
            WorkflowCollection::<ExampleState>::open_local(temp.path().join("workflow.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let recorded_at = OffsetDateTime::UNIX_EPOCH + Duration::seconds(90);
        let completed_at = recorded_at + Duration::seconds(15);

        let mut workflow = example_workflow();
        workflow
            .step_mut(1)
            .unwrap_or_else(|| panic!("missing apply step"))
            .begin_effect_at(
                "apply_restore",
                "idem-restore-1",
                Some(String::from("prepared")),
                recorded_at,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        workflow
            .step_mut(1)
            .unwrap_or_else(|| panic!("missing apply step"))
            .complete_effect_at(
                "apply_restore",
                Some("digest-restore-1"),
                Some(String::from("completed")),
                completed_at,
            )
            .unwrap_or_else(|error| panic!("{error}"));

        collection
            .create("wf-1", workflow)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let loaded = collection
            .get("wf-1")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing workflow"));
        let effect = loaded.value.steps[1]
            .effect("apply_restore")
            .unwrap_or_else(|| panic!("missing effect journal entry"));
        assert_eq!(effect.idempotency_key, "idem-restore-1");
        assert_eq!(effect.state, WorkflowStepEffectState::Completed);
        assert_eq!(effect.result_digest.as_deref(), Some("digest-restore-1"));
        assert_eq!(effect.recorded_at, recorded_at);
        assert_eq!(effect.completed_at, Some(completed_at));
    }

    #[test]
    fn workflow_effect_ledger_record_round_trips_identity() {
        let mut workflow = example_workflow();
        let recorded_at = OffsetDateTime::UNIX_EPOCH + Duration::seconds(120);
        workflow
            .step_mut(1)
            .unwrap_or_else(|| panic!("missing apply step"))
            .begin_effect_at(
                "apply_restore",
                "idem-restore-1",
                Some(String::from("prepared restore")),
                recorded_at - Duration::seconds(5),
            )
            .unwrap_or_else(|error| panic!("{error}"));

        let ledger = WorkflowEffectLedgerRecord::from_workflow_effect_at(
            &workflow,
            1,
            "apply_restore",
            "digest-restore-1",
            recorded_at,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(ledger.key(), "idem-restore-1");
        assert_eq!(ledger.workflow_id, "wf-1");
        assert_eq!(ledger.step_index, 1);
        assert_eq!(ledger.step_name, "apply");
        assert_eq!(ledger.effect_kind, "apply_restore");
        assert_eq!(ledger.result_digest, "digest-restore-1");
        assert_eq!(ledger.recorded_at, recorded_at);
        ledger
            .validate_for_workflow(&workflow)
            .unwrap_or_else(|error| panic!("{error}"));

        let mut tampered = workflow.clone();
        tampered.subject_id = String::from("different-subject");
        let error = ledger
            .validate_for_workflow(&tampered)
            .expect_err("tampered workflow identity should fail");
        assert_eq!(error.code, ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn workflow_collection_step_effect_helpers_persist_and_replay() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let collection =
            WorkflowCollection::<ExampleState>::open_local(temp.path().join("workflow.json"))
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        let journaled_at = OffsetDateTime::UNIX_EPOCH + Duration::seconds(140);
        let completed_at = journaled_at + Duration::seconds(10);

        collection
            .create("wf-1", example_workflow())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let (journaled, execution) = collection
            .begin_step_effect_at(
                "wf-1",
                1,
                "apply_restore",
                "idem-restore-1",
                Some(String::from("prepared restore")),
                journaled_at,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let pending = match execution {
            WorkflowStepEffectExecution::Execute(effect) => effect,
            WorkflowStepEffectExecution::Replay(_) => {
                panic!("first helper-based effect should execute")
            }
        };
        assert_eq!(journaled.value.steps[1].effect_journal.len(), 1);
        assert_eq!(pending.idempotency_key, "idem-restore-1");

        let (completed, effect) = collection
            .complete_step_effect_at(
                "wf-1",
                1,
                "apply_restore",
                Some("digest-restore-1"),
                Some(String::from("restore applied")),
                completed_at,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(effect.result_digest.as_deref(), Some("digest-restore-1"));
        assert_eq!(effect.completed_at, Some(completed_at));
        assert_eq!(
            completed.value.steps[1]
                .effect("apply_restore")
                .and_then(|entry| entry.result_digest.as_deref()),
            Some("digest-restore-1")
        );

        let (_replayed, replay) = collection
            .begin_step_effect_at(
                "wf-1",
                1,
                "apply_restore",
                "idem-restore-2",
                Some(String::from("should reuse persisted key")),
                completed_at + Duration::seconds(10),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let replay_effect = match replay {
            WorkflowStepEffectExecution::Replay(effect) => effect,
            WorkflowStepEffectExecution::Execute(_) => {
                panic!("completed helper-based effect should replay")
            }
        };
        assert_eq!(replay_effect.idempotency_key, "idem-restore-1");
        assert_eq!(
            replay_effect.result_digest.as_deref(),
            Some("digest-restore-1")
        );
    }

    #[test]
    fn workflow_runner_claims_heartbeat_and_takeover_are_fenced() {
        let mut workflow = example_workflow();
        let claimed_at = OffsetDateTime::UNIX_EPOCH + Duration::seconds(10);
        let original_claim = workflow
            .claim_runner_at("runner-a", Duration::seconds(30), claimed_at)
            .unwrap_or_else(|error| panic!("{error}"))
            .clone();
        assert_eq!(original_claim.runner_id, "runner-a");
        assert_eq!(original_claim.claimed_at, claimed_at);
        assert_eq!(original_claim.takeover_count, 0);
        assert!(workflow.has_active_runner_claim_at(claimed_at));

        let heartbeat_at = claimed_at + Duration::seconds(5);
        workflow
            .heartbeat_runner_at(
                "runner-a",
                original_claim.fencing_token.as_str(),
                Duration::seconds(30),
                heartbeat_at,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let heartbeated_claim = workflow
            .runner_claim
            .clone()
            .unwrap_or_else(|| panic!("missing claim after heartbeat"));
        assert_eq!(
            heartbeated_claim.fencing_token,
            original_claim.fencing_token
        );
        assert_eq!(heartbeated_claim.last_heartbeat_at, heartbeat_at);
        assert_eq!(
            heartbeated_claim.lease_expires_at,
            heartbeat_at + Duration::seconds(30)
        );

        let blocked_takeover = workflow
            .claim_runner_at("runner-b", Duration::seconds(30), heartbeat_at)
            .expect_err("active claim should block takeover");
        assert_eq!(blocked_takeover.code, ErrorCode::Conflict);

        let takeover_at = heartbeated_claim.lease_expires_at + Duration::seconds(1);
        let takeover_claim = workflow
            .claim_runner_at("runner-b", Duration::seconds(30), takeover_at)
            .unwrap_or_else(|error| panic!("{error}"))
            .clone();
        assert_eq!(takeover_claim.runner_id, "runner-b");
        assert_eq!(takeover_claim.takeover_count, 1);
        assert_ne!(takeover_claim.fencing_token, original_claim.fencing_token);

        let stale_heartbeat = workflow
            .heartbeat_runner_at(
                "runner-a",
                original_claim.fencing_token.as_str(),
                Duration::seconds(30),
                takeover_at,
            )
            .expect_err("stale fencing token should be rejected");
        assert_eq!(stale_heartbeat.code, ErrorCode::Conflict);

        workflow
            .assert_runner_fence_at(
                "runner-b",
                takeover_claim.fencing_token.as_str(),
                takeover_at,
            )
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn workflow_due_state_uses_next_attempt_timestamp() {
        let mut workflow = example_workflow();
        let now = OffsetDateTime::UNIX_EPOCH + Duration::seconds(20);
        let later = now + Duration::seconds(15);

        assert!(workflow.is_due_at(now));
        workflow.set_next_attempt_at(Some(later), now);
        assert!(!workflow.is_due_at(now));
        assert!(workflow.is_due_at(later));
    }
}
