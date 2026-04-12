use serde::{Deserialize, Serialize};
use uhost_core::{PlatformError, Result};

use crate::{
    BootDevice, ClaimTier, GuestArchitecture, GuestProfile, HostPlatform, HypervisorBackend,
    MachineFamily,
};

/// Source that produced a compatibility requirement or assessment evidence row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UvmCompatibilityEvidenceSource {
    /// Evidence derived from an image-plane import or promotion contract.
    ImageContract,
    /// Evidence derived from an execution-intent or portability contract.
    ExecutionIntent,
    /// Evidence derived from a node capability declaration.
    NodeCapability,
    /// Evidence derived from a runtime admission preflight.
    RuntimePreflight,
    /// Evidence derived from validation or benchmark reporting.
    ValidationReport,
}

impl UvmCompatibilityEvidenceSource {
    /// Stable string representation used by service responses and audits.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ImageContract => "image_contract",
            Self::ExecutionIntent => "execution_intent",
            Self::NodeCapability => "node_capability",
            Self::RuntimePreflight => "runtime_preflight",
            Self::ValidationReport => "validation_report",
        }
    }
}

/// Execution-envelope axis used by derived host-class keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostClassEnvironment {
    /// Native bare-metal or privileged host execution.
    BareMetal,
    /// Containerized or otherwise nested-virtualization-restricted execution.
    ContainerRestricted,
    /// Shared hosted-CI execution envelope.
    HostedCi,
    /// Operator-declared host envelope without direct measurement.
    OperatorDeclared,
}

impl HostClassEnvironment {
    /// Parse a stable host-class environment key.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "bare_metal" => Ok(Self::BareMetal),
            "container_restricted" => Ok(Self::ContainerRestricted),
            "hosted_ci" => Ok(Self::HostedCi),
            "operator_declared" => Ok(Self::OperatorDeclared),
            _ => Err(PlatformError::invalid(
                "host_class environment must be one of bare_metal/container_restricted/hosted_ci/operator_declared",
            )),
        }
    }

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BareMetal => "bare_metal",
            Self::ContainerRestricted => "container_restricted",
            Self::HostedCi => "hosted_ci",
            Self::OperatorDeclared => "operator_declared",
        }
    }
}

/// Canonical normalized host-class key shared across image, node, and observe surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostClass(String);

impl HostClass {
    /// Parse and normalize a shared host-class key.
    pub fn parse(value: &str) -> Result<Self> {
        let normalized = value.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return Err(PlatformError::invalid("host_class may not be empty"));
        }
        if normalized.len() > 128 {
            return Err(PlatformError::invalid("host_class exceeds 128 bytes"));
        }
        let is_valid = normalized.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '_' | '.')
        });
        if !is_valid {
            return Err(PlatformError::invalid(
                "host_class may only contain lowercase ascii letters, digits, dots, dashes, and underscores",
            ));
        }
        Ok(Self(normalized))
    }

    /// Derive a host-class key from host platform and environment axes.
    pub fn from_platform_environment(
        host_platform: HostPlatform,
        environment: HostClassEnvironment,
    ) -> Self {
        Self(format!(
            "{}_{}",
            host_platform.as_str(),
            environment.as_str()
        ))
    }

    /// Borrow the normalized host-class key.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the host class into its normalized key.
    pub fn into_string(self) -> String {
        self.0
    }
}

/// Shared compatibility requirement that image, node, and observe services can exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmCompatibilityRequirement {
    /// Guest architecture required by the contract.
    pub guest_architecture: GuestArchitecture,
    /// Machine family required by the contract.
    pub machine_family: MachineFamily,
    /// Guest profile required by the contract.
    pub guest_profile: GuestProfile,
    /// Preferred boot device for the contract.
    pub boot_device: BootDevice,
    /// Highest claim tier attached to this compatibility contract.
    pub claim_tier: ClaimTier,
}

impl UvmCompatibilityRequirement {
    /// Construct a compatibility requirement from typed values.
    pub fn new(
        guest_architecture: GuestArchitecture,
        machine_family: MachineFamily,
        guest_profile: GuestProfile,
        boot_device: BootDevice,
        claim_tier: ClaimTier,
    ) -> Self {
        Self {
            guest_architecture,
            machine_family,
            guest_profile,
            boot_device,
            claim_tier,
        }
    }

    /// Construct a compatibility requirement from stringly service fields.
    pub fn parse_keys(
        guest_architecture: GuestArchitecture,
        machine_family: &str,
        guest_profile: &str,
        boot_device: &str,
        claim_tier: &str,
    ) -> Result<Self> {
        Ok(Self {
            guest_architecture,
            machine_family: MachineFamily::parse(machine_family)?,
            guest_profile: GuestProfile::parse(guest_profile)?,
            boot_device: BootDevice::parse(boot_device)?,
            claim_tier: ClaimTier::parse(claim_tier)?,
        })
    }

    /// Describe mismatches between a provided requirement and the derived runtime requirement.
    pub fn mismatch_blockers(&self, derived: &Self) -> Vec<String> {
        let mut blockers = Vec::new();
        if self.guest_architecture != derived.guest_architecture {
            blockers.push(format!(
                "compatibility requirement guest_architecture {} does not match requested guest_architecture {}",
                self.guest_architecture.as_str(),
                derived.guest_architecture.as_str(),
            ));
        }
        if self.machine_family != derived.machine_family {
            blockers.push(format!(
                "compatibility requirement machine_family {} does not match derived machine_family {}",
                self.machine_family.as_str(),
                derived.machine_family.as_str(),
            ));
        }
        if self.guest_profile != derived.guest_profile {
            blockers.push(format!(
                "compatibility requirement guest_profile {} does not match derived guest_profile {}",
                self.guest_profile.as_str(),
                derived.guest_profile.as_str(),
            ));
        }
        if self.boot_device != derived.boot_device {
            blockers.push(format!(
                "compatibility requirement boot_device {} does not match requested boot_device {}",
                self.boot_device.as_str(),
                derived.boot_device.as_str(),
            ));
        }
        if self.claim_tier != derived.claim_tier {
            blockers.push(format!(
                "compatibility requirement claim_tier {} does not match capability claim_tier {}",
                self.claim_tier.as_str(),
                derived.claim_tier.as_str(),
            ));
        }
        blockers
    }
}

/// Human-readable evidence row attached to a compatibility requirement or assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmCompatibilityEvidence {
    /// Evidence source.
    pub source: UvmCompatibilityEvidenceSource,
    /// Short human-readable summary.
    pub summary: String,
    /// Optional evidence mode or posture tag when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_mode: Option<String>,
}

/// Typed summary of a node capability for compatibility assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmNodeCompatibilitySummary {
    /// Host platform family.
    pub host_platform: HostPlatform,
    /// Shared host-class key for the node posture.
    pub host_class: HostClass,
    /// Accelerator backends declared by the node.
    pub accelerator_backends: Vec<HypervisorBackend>,
    /// Machine families supported by the node.
    pub supported_machine_families: Vec<MachineFamily>,
    /// Guest profiles supported by the node.
    pub supported_guest_profiles: Vec<GuestProfile>,
    /// Whether the node can satisfy secure-boot admission.
    pub supports_secure_boot: bool,
    /// Whether the node can satisfy live-migration admission.
    pub supports_live_migration: bool,
    /// Optional evidence mode attached to the node posture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_mode: Option<String>,
}

impl UvmNodeCompatibilitySummary {
    /// Assess whether this node capability can satisfy the requirement.
    pub fn assess(
        &self,
        requirement: &UvmCompatibilityRequirement,
        require_secure_boot: bool,
        requires_live_migration: bool,
    ) -> UvmCompatibilityAssessment {
        let mut blockers = Vec::new();
        if !self
            .supported_machine_families
            .contains(&requirement.machine_family)
        {
            blockers.push(format!(
                "machine family {} is not supported by selected capability",
                requirement.machine_family.as_str(),
            ));
        }
        if !self
            .supported_guest_profiles
            .contains(&requirement.guest_profile)
        {
            blockers.push(format!(
                "guest profile {} is not supported by selected capability",
                requirement.guest_profile.as_str(),
            ));
        }
        if require_secure_boot && !self.supports_secure_boot {
            blockers.push(String::from(
                "selected capability does not support secure boot",
            ));
        }
        if requires_live_migration && !self.supports_live_migration {
            blockers.push(String::from(
                "selected capability does not support live migration",
            ));
        }

        let matched_backends = self
            .accelerator_backends
            .iter()
            .copied()
            .filter(|backend| {
                backend.supported_on_host(self.host_platform)
                    && backend.supports_guest_architecture(requirement.guest_architecture)
                    && (!require_secure_boot || backend.supports_secure_boot())
                    && (!requires_live_migration || backend.supports_live_migration())
            })
            .collect::<Vec<_>>();
        if matched_backends.is_empty() {
            blockers.push(format!(
                "no accelerator backend on host_class {} satisfies guest_architecture {}",
                self.host_class.as_str(),
                requirement.guest_architecture.as_str(),
            ));
        }

        let backend_keys = self
            .accelerator_backends
            .iter()
            .map(|backend| backend.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let machine_families = self
            .supported_machine_families
            .iter()
            .map(|family| family.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let guest_profiles = self
            .supported_guest_profiles
            .iter()
            .map(|profile| profile.as_str())
            .collect::<Vec<_>>()
            .join(",");

        let mut evidence = vec![UvmCompatibilityEvidence {
            source: UvmCompatibilityEvidenceSource::NodeCapability,
            summary: format!(
                "host_class={} host_platform={} accelerator_backends={} supported_machine_families={} supported_guest_profiles={}",
                self.host_class.as_str(),
                self.host_platform.as_str(),
                backend_keys,
                machine_families,
                guest_profiles,
            ),
            evidence_mode: self.evidence_mode.clone(),
        }];
        if !matched_backends.is_empty() {
            evidence.push(UvmCompatibilityEvidence {
                source: UvmCompatibilityEvidenceSource::RuntimePreflight,
                summary: format!(
                    "matched_backends={}",
                    matched_backends
                        .iter()
                        .map(|backend| backend.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                evidence_mode: None,
            });
        }

        UvmCompatibilityAssessment {
            requirement: requirement.clone(),
            supported: blockers.is_empty(),
            matched_backends,
            blockers,
            evidence,
        }
    }
}

/// Compatibility assessment emitted by node or observe services.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmCompatibilityAssessment {
    /// Requirement being evaluated.
    pub requirement: UvmCompatibilityRequirement,
    /// Whether the requirement is currently satisfied.
    pub supported: bool,
    /// Backends that satisfy the requirement on the evaluated node or evidence set.
    pub matched_backends: Vec<HypervisorBackend>,
    /// Human-readable blockers for unsupported cases.
    pub blockers: Vec<String>,
    /// Evidence rows explaining the assessment.
    pub evidence: Vec<UvmCompatibilityEvidence>,
}

#[cfg(test)]
mod tests {
    use super::{
        HostClass, HostClassEnvironment, UvmCompatibilityEvidenceSource,
        UvmCompatibilityRequirement, UvmNodeCompatibilitySummary,
    };
    use crate::{
        BootDevice, ClaimTier, GuestArchitecture, GuestProfile, HostPlatform, HypervisorBackend,
        MachineFamily,
    };

    #[test]
    fn mismatch_blockers_capture_boot_and_profile_drift() {
        let imported = UvmCompatibilityRequirement::new(
            GuestArchitecture::X86_64,
            MachineFamily::GeneralPurposePci,
            GuestProfile::WindowsGeneral,
            BootDevice::Cdrom,
            ClaimTier::Competitive,
        );
        let derived = UvmCompatibilityRequirement::new(
            GuestArchitecture::X86_64,
            MachineFamily::GeneralPurposePci,
            GuestProfile::LinuxStandard,
            BootDevice::Disk,
            ClaimTier::Compatible,
        );

        let blockers = imported.mismatch_blockers(&derived);
        assert!(blockers.iter().any(|value| value.contains("guest_profile")));
        assert!(blockers.iter().any(|value| value.contains("boot_device")));
        assert!(blockers.iter().any(|value| value.contains("claim_tier")));
    }

    #[test]
    fn host_class_supports_shared_keys_and_derived_platform_envelopes() {
        assert_eq!(
            HostClass::parse("default")
                .unwrap_or_else(|error| panic!("{error}"))
                .as_str(),
            "default"
        );
        assert_eq!(
            HostClass::from_platform_environment(
                HostPlatform::Linux,
                HostClassEnvironment::HostedCi,
            )
            .as_str(),
            "linux_hosted_ci"
        );
    }

    #[test]
    fn node_summary_assess_reports_matching_backend_and_evidence() {
        let summary = UvmNodeCompatibilitySummary {
            host_platform: HostPlatform::Linux,
            host_class: HostClass::from_platform_environment(
                HostPlatform::Linux,
                HostClassEnvironment::BareMetal,
            ),
            accelerator_backends: vec![HypervisorBackend::SoftwareDbt, HypervisorBackend::Kvm],
            supported_machine_families: vec![
                MachineFamily::GeneralPurposePci,
                MachineFamily::MicrovmLinux,
            ],
            supported_guest_profiles: vec![
                GuestProfile::LinuxStandard,
                GuestProfile::LinuxDirectKernel,
            ],
            supports_secure_boot: true,
            supports_live_migration: true,
            evidence_mode: Some(String::from("direct_host")),
        };
        let requirement = UvmCompatibilityRequirement::new(
            GuestArchitecture::X86_64,
            MachineFamily::GeneralPurposePci,
            GuestProfile::LinuxStandard,
            BootDevice::Disk,
            ClaimTier::Compatible,
        );

        let assessment = summary.assess(&requirement, false, false);
        assert!(assessment.supported);
        assert!(
            assessment
                .matched_backends
                .contains(&HypervisorBackend::SoftwareDbt)
        );
        assert!(assessment.evidence.iter().any(|row| {
            row.source == UvmCompatibilityEvidenceSource::NodeCapability
                && row.evidence_mode.as_deref() == Some("direct_host")
        }));
    }
}
