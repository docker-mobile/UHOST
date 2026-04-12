use serde::{Deserialize, Serialize};
use uhost_core::{PlatformError, Result};

use crate::{
    BackendSelectionRequest, ClaimEvidenceMode, GuestProfile, HypervisorBackend,
    compatibility::{UvmCompatibilityEvidence, UvmCompatibilityEvidenceSource},
    select_backend,
};

/// Fallback policy applied when the preferred backend is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UvmBackendFallbackPolicy {
    /// Allow node admission to choose another compatible backend.
    AllowCompatible,
    /// Reject admission unless the preferred backend itself is available.
    RequirePreferred,
}

impl UvmBackendFallbackPolicy {
    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllowCompatible => "allow_compatible",
            Self::RequirePreferred => "require_preferred",
        }
    }
}

/// Portability tier required by the execution contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UvmPortabilityTier {
    /// Permit any compatible backend, including the portable software path.
    Portable,
    /// Require an accelerated backend and reject software-only placement.
    AcceleratorRequired,
    /// Require a host-specific preferred backend.
    HostSpecific,
}

impl UvmPortabilityTier {
    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Portable => "portable",
            Self::AcceleratorRequired => "accelerator_required",
            Self::HostSpecific => "host_specific",
        }
    }
}

/// Evidence strictness required before a portability claim may be admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UvmEvidenceStrictness {
    /// Simulated or measured node evidence is acceptable.
    AllowSimulated,
    /// Node evidence must come from a directly measured host posture.
    RequireMeasured,
}

impl UvmEvidenceStrictness {
    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllowSimulated => "allow_simulated",
            Self::RequireMeasured => "require_measured",
        }
    }
}

/// Backend-agnostic execution intent exchanged between image, control, and node paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmExecutionIntent {
    /// Preferred backend when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_backend: Option<HypervisorBackend>,
    /// Fallback policy when the preferred backend is unavailable.
    #[serde(default = "default_fallback_policy")]
    pub fallback_policy: UvmBackendFallbackPolicy,
    /// Required portability tier for admission.
    #[serde(default = "default_portability_tier")]
    pub required_portability_tier: UvmPortabilityTier,
    /// Evidence strictness for the currently implemented slice.
    #[serde(default = "default_evidence_strictness")]
    pub evidence_strictness: UvmEvidenceStrictness,
}

fn default_fallback_policy() -> UvmBackendFallbackPolicy {
    UvmBackendFallbackPolicy::AllowCompatible
}

fn default_portability_tier() -> UvmPortabilityTier {
    UvmPortabilityTier::Portable
}

fn default_evidence_strictness() -> UvmEvidenceStrictness {
    UvmEvidenceStrictness::AllowSimulated
}

impl Default for UvmExecutionIntent {
    fn default() -> Self {
        Self {
            preferred_backend: None,
            fallback_policy: default_fallback_policy(),
            required_portability_tier: default_portability_tier(),
            evidence_strictness: default_evidence_strictness(),
        }
    }
}

impl UvmExecutionIntent {
    /// Derive the default execution intent for a guest profile.
    pub fn default_for_guest_profile(profile: GuestProfile) -> Self {
        match profile {
            GuestProfile::AppleGuest => Self {
                preferred_backend: Some(HypervisorBackend::AppleVirtualization),
                fallback_policy: UvmBackendFallbackPolicy::RequirePreferred,
                required_portability_tier: UvmPortabilityTier::HostSpecific,
                evidence_strictness: UvmEvidenceStrictness::RequireMeasured,
            },
            _ => Self::default(),
        }
    }
}

/// Provenance marker describing how a portability assessment was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UvmPortabilityAssessmentSource {
    /// Resolved from runtime-session first-placement lineage.
    FirstPlacementLineage,
    /// Resolved from a runtime-preflight assessment linked through runtime-session lineage.
    LinkedRuntimePreflightLineage,
    /// Resolved from a runtime-preflight record after durable lineage produced no winner.
    RuntimePreflightFallback,
    /// Resolved from explicit claim-decision inputs after durable lineage and runtime-preflight data produced no winner.
    RequestFallback,
    /// No portability assessment was available to resolve.
    #[default]
    Unavailable,
}

impl UvmPortabilityAssessmentSource {
    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FirstPlacementLineage => "first_placement_lineage",
            Self::LinkedRuntimePreflightLineage => "linked_runtime_preflight_lineage",
            Self::RuntimePreflightFallback => "runtime_preflight_fallback",
            Self::RequestFallback => "request_fallback",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Stable reason describing why no portability assessment could be surfaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UvmPortabilityAssessmentUnavailableReason {
    /// Current authoritative runtime lineage exists, but it does not currently carry
    /// first-placement or linked-preflight portability evidence.
    AuthoritativeRuntimeLineageMissingPortabilityEvidence,
}

impl UvmPortabilityAssessmentUnavailableReason {
    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthoritativeRuntimeLineageMissingPortabilityEvidence => {
                "authoritative_runtime_lineage_missing_portability_evidence"
            }
        }
    }
}

/// Structured portability assessment produced from an execution intent and node candidates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmPortabilityAssessment {
    /// Intent evaluated by the assessment.
    pub intent: UvmExecutionIntent,
    /// Whether the intent is currently satisfiable.
    pub supported: bool,
    /// Backends still eligible after portability filtering.
    pub eligible_backends: Vec<HypervisorBackend>,
    /// Selected backend when the intent is satisfiable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_backend: Option<HypervisorBackend>,
    /// Whether selection required fallback from the preferred backend.
    #[serde(default)]
    pub selected_via_fallback: bool,
    /// Stable human-readable selection reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_reason: Option<String>,
    /// Hard blockers that deny portability admission.
    pub blockers: Vec<String>,
    /// Evidence rows explaining the assessment.
    pub evidence: Vec<UvmCompatibilityEvidence>,
}

fn effective_claim_evidence_mode(value: Option<&str>) -> ClaimEvidenceMode {
    if matches!(value, Some("direct_host")) {
        ClaimEvidenceMode::Measured
    } else {
        ClaimEvidenceMode::Simulated
    }
}

fn candidate_satisfies_request(
    candidate: HypervisorBackend,
    request: &BackendSelectionRequest,
) -> bool {
    candidate.supported_on_host(request.host)
        && candidate.supports_guest_architecture(request.guest_architecture)
        && (!request.requires_live_migration || candidate.supports_live_migration())
        && (!request.require_secure_boot || candidate.supports_secure_boot())
        && (!request.apple_guest || candidate == HypervisorBackend::AppleVirtualization)
}

/// Assess execution intent against a backend-selection request.
pub fn assess_execution_intent(
    request: &BackendSelectionRequest,
    intent: Option<&UvmExecutionIntent>,
    evidence_mode: Option<&str>,
) -> Result<UvmPortabilityAssessment> {
    if request.candidates.is_empty() {
        return Err(PlatformError::invalid(
            "backend candidate list may not be empty",
        ));
    }

    let intent = intent.cloned().unwrap_or_default();
    let effective_evidence_mode = effective_claim_evidence_mode(evidence_mode);
    let mut blockers = Vec::new();
    if intent.evidence_strictness == UvmEvidenceStrictness::RequireMeasured
        && effective_evidence_mode != ClaimEvidenceMode::Measured
    {
        blockers.push(format!(
            "execution intent evidence_strictness {} requires measured evidence, got {}",
            intent.evidence_strictness.as_str(),
            effective_evidence_mode.as_str()
        ));
    }

    let mut eligible_backends = request
        .candidates
        .iter()
        .copied()
        .filter(|candidate| candidate_satisfies_request(*candidate, request))
        .collect::<Vec<_>>();

    match intent.required_portability_tier {
        UvmPortabilityTier::Portable => {}
        UvmPortabilityTier::AcceleratorRequired => {
            eligible_backends.retain(|candidate| *candidate != HypervisorBackend::SoftwareDbt);
            if eligible_backends.is_empty() {
                blockers.push(String::from(
                    "execution intent portability tier accelerator_required excludes software_dbt fallback on this capability",
                ));
            }
        }
        UvmPortabilityTier::HostSpecific => {
            if let Some(preferred_backend) = intent.preferred_backend {
                eligible_backends.retain(|candidate| *candidate == preferred_backend);
                if eligible_backends.is_empty() {
                    blockers.push(format!(
                        "execution intent portability tier host_specific requires preferred backend {}",
                        preferred_backend.as_str()
                    ));
                }
            } else {
                eligible_backends.clear();
                blockers.push(String::from(
                    "execution intent portability tier host_specific requires preferred_backend",
                ));
            }
        }
    }

    let mut selected_backend = None;
    let mut selected_via_fallback = false;
    let mut selection_reason = None;

    if let Some(preferred_backend) = intent.preferred_backend {
        if eligible_backends.contains(&preferred_backend) {
            selected_backend = Some(preferred_backend);
            selection_reason = Some(format!(
                "selected preferred backend {} from execution intent",
                preferred_backend.as_str()
            ));
        } else if intent.fallback_policy == UvmBackendFallbackPolicy::AllowCompatible
            && !eligible_backends.is_empty()
            && intent.required_portability_tier != UvmPortabilityTier::HostSpecific
        {
            let fallback_selection = select_backend(&BackendSelectionRequest {
                candidates: eligible_backends.clone(),
                ..request.clone()
            })?;
            selected_backend = Some(fallback_selection.backend);
            selected_via_fallback = true;
            selection_reason = Some(format!(
                "preferred backend {} unavailable; fell back to {} under fallback policy {}",
                preferred_backend.as_str(),
                fallback_selection.backend.as_str(),
                intent.fallback_policy.as_str()
            ));
        } else {
            blockers.push(format!(
                "preferred backend {} is not eligible on host {} for guest_architecture {}",
                preferred_backend.as_str(),
                request.host.as_str(),
                request.guest_architecture.as_str()
            ));
        }
    } else if !eligible_backends.is_empty() {
        let selection = select_backend(&BackendSelectionRequest {
            candidates: eligible_backends.clone(),
            ..request.clone()
        })?;
        selected_backend = Some(selection.backend);
        selection_reason = Some(selection.reason);
    } else if blockers.is_empty() {
        blockers.push(
            select_backend(request)
                .err()
                .map(|error| error.message)
                .unwrap_or_else(|| {
                    String::from("no compatible backend candidate satisfied admission requirements")
                }),
        );
    }

    let eligible_keys = eligible_backends
        .iter()
        .map(|backend| backend.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let mut evidence = vec![UvmCompatibilityEvidence {
        source: UvmCompatibilityEvidenceSource::ExecutionIntent,
        summary: format!(
            "preferred_backend={} fallback_policy={} required_portability_tier={} evidence_strictness={}",
            intent
                .preferred_backend
                .map(HypervisorBackend::as_str)
                .unwrap_or("none"),
            intent.fallback_policy.as_str(),
            intent.required_portability_tier.as_str(),
            intent.evidence_strictness.as_str(),
        ),
        evidence_mode: Some(String::from(effective_evidence_mode.as_str())),
    }];
    evidence.push(UvmCompatibilityEvidence {
        source: UvmCompatibilityEvidenceSource::RuntimePreflight,
        summary: format!("eligible_backends={eligible_keys}"),
        evidence_mode: None,
    });
    if let Some(selected_backend) = selected_backend {
        evidence.push(UvmCompatibilityEvidence {
            source: UvmCompatibilityEvidenceSource::RuntimePreflight,
            summary: format!(
                "selected_backend={} selected_via_fallback={selected_via_fallback}",
                selected_backend.as_str()
            ),
            evidence_mode: None,
        });
    }

    Ok(UvmPortabilityAssessment {
        intent,
        supported: blockers.is_empty(),
        eligible_backends,
        selected_backend,
        selected_via_fallback,
        selection_reason,
        blockers,
        evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        UvmBackendFallbackPolicy, UvmEvidenceStrictness, UvmExecutionIntent, UvmPortabilityTier,
        assess_execution_intent,
    };
    use crate::{
        BackendSelectionRequest, GuestArchitecture, HostPlatform, HypervisorBackend,
        UvmCompatibilityEvidenceSource,
    };

    #[test]
    fn default_intent_preserves_existing_backend_preference() {
        let request = BackendSelectionRequest {
            host: HostPlatform::Linux,
            candidates: vec![HypervisorBackend::SoftwareDbt, HypervisorBackend::Kvm],
            guest_architecture: GuestArchitecture::X86_64,
            apple_guest: false,
            requires_live_migration: false,
            require_secure_boot: false,
        };

        let assessment = assess_execution_intent(&request, None, Some("direct_host"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(assessment.supported);
        assert_eq!(assessment.selected_backend, Some(HypervisorBackend::Kvm));
        assert!(!assessment.selected_via_fallback);
        assert_eq!(
            assessment.selection_reason.as_deref(),
            Some("selected kvm from compatibility preference")
        );
    }

    #[test]
    fn require_preferred_backend_rejects_unsupported_preference() {
        let request = BackendSelectionRequest {
            host: HostPlatform::Linux,
            candidates: vec![HypervisorBackend::SoftwareDbt],
            guest_architecture: GuestArchitecture::X86_64,
            apple_guest: false,
            requires_live_migration: false,
            require_secure_boot: false,
        };
        let intent = UvmExecutionIntent {
            preferred_backend: Some(HypervisorBackend::Kvm),
            fallback_policy: UvmBackendFallbackPolicy::RequirePreferred,
            required_portability_tier: UvmPortabilityTier::Portable,
            evidence_strictness: UvmEvidenceStrictness::AllowSimulated,
        };

        let assessment = assess_execution_intent(&request, Some(&intent), Some("direct_host"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!assessment.supported);
        assert!(assessment.selected_backend.is_none());
        assert!(
            assessment
                .blockers
                .iter()
                .any(|value| value.contains("preferred backend kvm"))
        );
        assert!(
            assessment
                .evidence
                .iter()
                .any(|row| { row.source == UvmCompatibilityEvidenceSource::ExecutionIntent })
        );
    }

    #[test]
    fn allow_compatible_falls_back_when_preferred_backend_is_unavailable() {
        let request = BackendSelectionRequest {
            host: HostPlatform::Linux,
            candidates: vec![HypervisorBackend::SoftwareDbt],
            guest_architecture: GuestArchitecture::X86_64,
            apple_guest: false,
            requires_live_migration: false,
            require_secure_boot: false,
        };
        let intent = UvmExecutionIntent {
            preferred_backend: Some(HypervisorBackend::Kvm),
            fallback_policy: UvmBackendFallbackPolicy::AllowCompatible,
            required_portability_tier: UvmPortabilityTier::Portable,
            evidence_strictness: UvmEvidenceStrictness::AllowSimulated,
        };

        let assessment = assess_execution_intent(&request, Some(&intent), Some("direct_host"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(assessment.supported);
        assert_eq!(
            assessment.selected_backend,
            Some(HypervisorBackend::SoftwareDbt)
        );
        assert!(assessment.selected_via_fallback);
        assert_eq!(
            assessment.selection_reason.as_deref(),
            Some(
                "preferred backend kvm unavailable; fell back to software_dbt under fallback policy allow_compatible"
            )
        );
    }
}
