//! UVM core execution and compatibility primitives.
//!
//! This crate provides the shared, dependency-starved execution logic that the
//! UVM node plane relies on:
//! - host/backend compatibility and legal guardrails
//! - deterministic VM runtime state transitions
//! - launch command construction for adapter backends
//! - migration envelope hashing used for checkpoint integrity tracking
//!
//! The code intentionally avoids direct hypervisor syscalls today and instead
//! codifies explicit contracts and invariants so platform adapters can evolve
//! behind stable types.

pub mod compatibility;
pub mod engine;
pub mod intent;
pub mod validation;

pub use compatibility::{
    HostClass, HostClassEnvironment, UvmCompatibilityAssessment, UvmCompatibilityEvidence,
    UvmCompatibilityEvidenceSource, UvmCompatibilityRequirement, UvmNodeCompatibilitySummary,
};

pub use engine::{
    BootPath, DeviceModel, ExecutionClass, ExecutionPlanRequest, MemoryBacking, SandboxLayer,
    TelemetryStream, UvmExecutionPlan, synthesize_execution_plan,
};

pub use intent::{
    UvmBackendFallbackPolicy, UvmEvidenceStrictness, UvmExecutionIntent, UvmPortabilityAssessment,
    UvmPortabilityAssessmentSource, UvmPortabilityAssessmentUnavailableReason, UvmPortabilityTier,
    assess_execution_intent,
};

pub use validation::{
    BenchmarkScenarioResult, BenchmarkWorkload, ComparativeMetrics, EngineComparison,
    EnvironmentProbe, ExecutionEnvironment, FaultInjectionSummary, HostCapacityProfile,
    HostEvidence, IsolationAttestationReport, IsolationAttestationVerdict,
    IsolationControlEvidence, IsolationControlStatus, IsolationEvidenceSource, MeasurementMode,
    StressPhaseResult, UvmStackArchitecture, ValidationReport, ValidationTarget,
    gather_host_evidence, generate_validation_report, infer_host_capacity_profile,
    probe_environment, reference_stack_architecture,
};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uhost_core::{PlatformError, Result, sha256_hex};

/// Supported guest CPU architecture targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestArchitecture {
    /// x86_64 guests.
    X86_64,
    /// AArch64 guests.
    Aarch64,
}

impl GuestArchitecture {
    /// Parse a guest architecture value from operator/API input.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "x86_64" => Ok(Self::X86_64),
            "aarch64" => Ok(Self::Aarch64),
            _ => Err(PlatformError::invalid(
                "guest architecture must be `x86_64` or `aarch64`",
            )),
        }
    }

    /// Stable string representation used in API responses and audits.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

/// Host platform family used for backend compatibility checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostPlatform {
    /// Linux hosts.
    Linux,
    /// Windows hosts.
    Windows,
    /// macOS hosts.
    Macos,
    /// FreeBSD hosts.
    FreeBsd,
    /// OpenBSD hosts.
    OpenBsd,
    /// NetBSD hosts.
    NetBsd,
    /// DragonFlyBSD hosts.
    DragonFlyBsd,
    /// illumos-like hosts.
    Illumos,
    /// Any unsupported/unknown target family.
    Other,
}

impl HostPlatform {
    /// Parse a stable host platform key from persisted capability metadata.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "linux" => Ok(Self::Linux),
            "windows" => Ok(Self::Windows),
            "macos" => Ok(Self::Macos),
            "freebsd" | "free_bsd" => Ok(Self::FreeBsd),
            "openbsd" | "open_bsd" => Ok(Self::OpenBsd),
            "netbsd" | "net_bsd" => Ok(Self::NetBsd),
            "dragonflybsd" | "dragonfly_bsd" => Ok(Self::DragonFlyBsd),
            "illumos" | "solaris" => Ok(Self::Illumos),
            "other" => Ok(Self::Other),
            _ => Err(PlatformError::invalid(
                "host platform must be one of linux/windows/macos/freebsd/openbsd/netbsd/dragonflybsd/illumos/other",
            )),
        }
    }

    /// Detect host platform at compile-time/runtime boundary.
    pub fn current() -> Self {
        if cfg!(target_os = "linux") {
            return Self::Linux;
        }
        if cfg!(target_os = "windows") {
            return Self::Windows;
        }
        if cfg!(target_os = "macos") {
            return Self::Macos;
        }
        if cfg!(target_os = "freebsd") {
            return Self::FreeBsd;
        }
        if cfg!(target_os = "openbsd") {
            return Self::OpenBsd;
        }
        if cfg!(target_os = "netbsd") {
            return Self::NetBsd;
        }
        if cfg!(target_os = "dragonfly") {
            return Self::DragonFlyBsd;
        }
        if cfg!(target_os = "illumos") || cfg!(target_os = "solaris") {
            return Self::Illumos;
        }
        Self::Other
    }

    /// Stable string representation used in persisted capability records.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::FreeBsd => "freebsd",
            Self::OpenBsd => "openbsd",
            Self::NetBsd => "netbsd",
            Self::DragonFlyBsd => "dragonflybsd",
            Self::Illumos => "illumos",
            Self::Other => "other",
        }
    }
}

/// Machine family used to keep VM contracts stable across runtime adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineFamily {
    /// Minimal Linux-first microvm path.
    MicrovmLinux,
    /// General-purpose PCI/firmware path for broader guest compatibility.
    GeneralPurposePci,
    /// AArch64 virt-style machine family.
    Aarch64Virt,
}

impl MachineFamily {
    /// Parse a stable machine-family key.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "microvm_linux" => Ok(Self::MicrovmLinux),
            "general_purpose_pci" => Ok(Self::GeneralPurposePci),
            "aarch64_virt" => Ok(Self::Aarch64Virt),
            _ => Err(PlatformError::invalid(
                "machine family must be one of microvm_linux/general_purpose_pci/aarch64_virt",
            )),
        }
    }

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MicrovmLinux => "microvm_linux",
            Self::GeneralPurposePci => "general_purpose_pci",
            Self::Aarch64Virt => "aarch64_virt",
        }
    }

    /// Derive a conservative default machine-family choice from guest shape.
    pub fn default_for_guest(architecture: GuestArchitecture, guest_os: &str) -> Self {
        let normalized = guest_os.trim().to_ascii_lowercase();
        if architecture == GuestArchitecture::Aarch64 {
            return Self::Aarch64Virt;
        }
        if normalized == "linux" {
            return Self::GeneralPurposePci;
        }
        Self::GeneralPurposePci
    }
}

/// Guest-profile contract used for compatibility, image policy, and execution planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestProfile {
    /// Linux image expected to use the direct-kernel fast path.
    LinuxDirectKernel,
    /// Linux image expected to boot through a broader general-purpose flow.
    LinuxStandard,
    /// Windows compatibility profile.
    WindowsGeneral,
    /// BSD compatibility profile.
    BsdGeneral,
    /// Apple guest compatibility profile under legal guardrails.
    AppleGuest,
}

impl GuestProfile {
    /// Parse a stable guest-profile key.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "linux_direct_kernel" => Ok(Self::LinuxDirectKernel),
            "linux_standard" => Ok(Self::LinuxStandard),
            "windows_general" => Ok(Self::WindowsGeneral),
            "bsd_general" => Ok(Self::BsdGeneral),
            "apple_guest" => Ok(Self::AppleGuest),
            _ => Err(PlatformError::invalid(
                "guest profile must be one of linux_direct_kernel/linux_standard/windows_general/bsd_general/apple_guest",
            )),
        }
    }

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinuxDirectKernel => "linux_direct_kernel",
            Self::LinuxStandard => "linux_standard",
            Self::WindowsGeneral => "windows_general",
            Self::BsdGeneral => "bsd_general",
            Self::AppleGuest => "apple_guest",
        }
    }

    /// Derive a conservative default guest-profile choice from a guest OS hint.
    pub fn default_for_guest(guest_os: &str) -> Self {
        match guest_os.trim().to_ascii_lowercase().as_str() {
            "linux" => Self::LinuxStandard,
            "windows" => Self::WindowsGeneral,
            "freebsd" | "openbsd" | "netbsd" | "dragonflybsd" | "bsd" => Self::BsdGeneral,
            "macos" | "darwin" | "apple" => Self::AppleGuest,
            _ => Self::LinuxStandard,
        }
    }
}

/// Evidence-gated claim tier for compatibility and performance assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimTier {
    /// The workload boots and runs correctly.
    Compatible,
    /// The workload is within an agreed competitive band.
    Competitive,
    /// Boot path is faster for the named workload class.
    FasterBootPath,
    /// Density or clone fanout is better for the named workload class.
    FasterDensity,
    /// Faster-than-KVM claim for a specific measured workload class.
    FasterThanKvmForWorkloadClass,
    /// Research-only target with no approved production claim.
    ResearchOnly,
}

impl ClaimTier {
    /// Parse a stable claim-tier key.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "compatible" => Ok(Self::Compatible),
            "competitive" => Ok(Self::Competitive),
            "faster_boot_path" => Ok(Self::FasterBootPath),
            "faster_density" => Ok(Self::FasterDensity),
            "faster_than_kvm_for_workload_class" => Ok(Self::FasterThanKvmForWorkloadClass),
            "research_only" => Ok(Self::ResearchOnly),
            _ => Err(PlatformError::invalid(
                "claim tier must be one of compatible/competitive/faster_boot_path/faster_density/faster_than_kvm_for_workload_class/research_only",
            )),
        }
    }

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compatible => "compatible",
            Self::Competitive => "competitive",
            Self::FasterBootPath => "faster_boot_path",
            Self::FasterDensity => "faster_density",
            Self::FasterThanKvmForWorkloadClass => "faster_than_kvm_for_workload_class",
            Self::ResearchOnly => "research_only",
        }
    }
}

/// Claim evidence mode for truth-in-claims reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimEvidenceMode {
    /// Claim is backed by direct measurement.
    Measured,
    /// Claim is inferred or simulated.
    Simulated,
    /// Claim is not allowed in the current evidence envelope.
    Prohibited,
}

impl ClaimEvidenceMode {
    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::Simulated => "simulated",
            Self::Prohibited => "prohibited",
        }
    }
}

/// Stable migration policy requested by the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPolicy {
    /// Only stop-and-copy migration is allowed.
    ColdOnly,
    /// Live migration is preferred when possible, but cold migration is still allowed.
    BestEffortLive,
    /// Live migration is required.
    StrictLive,
    /// Live post-copy migration is required.
    LivePostCopy,
}

impl MigrationPolicy {
    /// Parse a stable migration-policy key.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "cold_only" => Ok(Self::ColdOnly),
            "best_effort_live" => Ok(Self::BestEffortLive),
            "strict_live" => Ok(Self::StrictLive),
            "live_postcopy" => Ok(Self::LivePostCopy),
            _ => Err(PlatformError::invalid(
                "migration_policy must be `cold_only`, `best_effort_live`, `strict_live`, or `live_postcopy`",
            )),
        }
    }

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ColdOnly => "cold_only",
            Self::BestEffortLive => "best_effort_live",
            Self::StrictLive => "strict_live",
            Self::LivePostCopy => "live_postcopy",
        }
    }

    /// Lossy migration-strategy projection for lower-level planning.
    pub fn strategy(self) -> MigrationStrategy {
        match self {
            Self::ColdOnly => MigrationStrategy::Cold,
            Self::BestEffortLive | Self::StrictLive => MigrationStrategy::LivePreCopy,
            Self::LivePostCopy => MigrationStrategy::LivePostCopy,
        }
    }

    /// Contract-tier implied by this migration policy.
    pub fn policy_tier(self) -> MigrationPolicyTier {
        match self {
            Self::ColdOnly => MigrationPolicyTier::StopAndCopy,
            Self::BestEffortLive => MigrationPolicyTier::LiveOptional,
            Self::StrictLive | Self::LivePostCopy => MigrationPolicyTier::LiveRequired,
        }
    }
}

/// Stable restore-policy tier for one UVM contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestorePolicyTier {
    /// Restore the latest eligible checkpoint lineage.
    LatestCheckpoint,
}

impl RestorePolicyTier {
    /// Parse a stable restore-policy tier key.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "latest_checkpoint" => Ok(Self::LatestCheckpoint),
            _ => Err(PlatformError::invalid(
                "restore_policy_tier must be `latest_checkpoint`",
            )),
        }
    }

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LatestCheckpoint => "latest_checkpoint",
        }
    }
}

/// Stable migration-policy tier for one UVM contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPolicyTier {
    /// Only stop-and-copy migration is allowed.
    StopAndCopy,
    /// Live migration is allowed but not mandatory.
    LiveOptional,
    /// Live migration is mandatory.
    LiveRequired,
}

impl MigrationPolicyTier {
    /// Parse a stable migration-policy tier key.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "stop_and_copy" => Ok(Self::StopAndCopy),
            "live_optional" => Ok(Self::LiveOptional),
            "live_required" => Ok(Self::LiveRequired),
            _ => Err(PlatformError::invalid(
                "migration_policy_tier must be `stop_and_copy`, `live_optional`, or `live_required`",
            )),
        }
    }

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StopAndCopy => "stop_and_copy",
            Self::LiveOptional => "live_optional",
            Self::LiveRequired => "live_required",
        }
    }

    /// Derive the tier implied by a concrete migration policy.
    pub fn for_policy(policy: MigrationPolicy) -> Self {
        policy.policy_tier()
    }

    /// Apply an inherited tier cap to a concrete requested migration policy.
    pub fn downgrade_for_policy(self, policy: MigrationPolicy) -> Self {
        self.min(Self::for_policy(policy))
    }
}

/// Runtime adapter backend families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypervisorBackend {
    /// Portable userspace software VM backend using dynamic binary translation.
    SoftwareDbt,
    /// Linux KVM backend.
    Kvm,
    /// Windows Hyper-V / WHP backend.
    HypervWhp,
    /// Apple Virtualization backend.
    AppleVirtualization,
    /// bhyve backend for BSD family.
    Bhyve,
}

/// Health state reported by a host-side hypervisor adapter heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypervisorHealth {
    /// Runtime has not yet reported a health state.
    Unknown,
    /// Runtime is healthy and progressing normally.
    Healthy,
    /// Runtime is serving workloads but has degraded characteristics.
    Degraded,
    /// Runtime or adapter is in a failed state.
    Failed,
}

impl HypervisorHealth {
    /// Parse a hypervisor health value from API or persisted state.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "unknown" => Ok(Self::Unknown),
            "healthy" => Ok(Self::Healthy),
            "degraded" => Ok(Self::Degraded),
            "failed" => Ok(Self::Failed),
            _ => Err(PlatformError::invalid(
                "hypervisor health must be one of unknown/healthy/degraded/failed",
            )),
        }
    }

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
        }
    }
}

impl HypervisorBackend {
    /// Parse backend string.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "software_dbt" => Ok(Self::SoftwareDbt),
            "kvm" => Ok(Self::Kvm),
            "hyperv_whp" => Ok(Self::HypervWhp),
            "apple_virtualization" => Ok(Self::AppleVirtualization),
            "bhyve" => Ok(Self::Bhyve),
            _ => Err(PlatformError::invalid(
                "backend must be one of software_dbt/kvm/hyperv_whp/apple_virtualization/bhyve",
            )),
        }
    }

    /// Stable backend key string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SoftwareDbt => "software_dbt",
            Self::Kvm => "kvm",
            Self::HypervWhp => "hyperv_whp",
            Self::AppleVirtualization => "apple_virtualization",
            Self::Bhyve => "bhyve",
        }
    }

    /// Whether backend is expected to support live migration primitives.
    pub fn supports_live_migration(self) -> bool {
        match self {
            Self::SoftwareDbt => false,
            Self::Kvm => true,
            Self::HypervWhp => true,
            Self::AppleVirtualization => false,
            Self::Bhyve => false,
        }
    }

    /// Whether backend is expected to support secure boot in UVM policy model.
    pub fn supports_secure_boot(self) -> bool {
        match self {
            Self::SoftwareDbt => true,
            Self::Kvm => true,
            Self::HypervWhp => true,
            Self::AppleVirtualization => true,
            Self::Bhyve => false,
        }
    }

    /// Whether backend is considered valid on the given host family.
    pub fn supported_on_host(self, host: HostPlatform) -> bool {
        match self {
            Self::SoftwareDbt => true,
            Self::Kvm => matches!(host, HostPlatform::Linux),
            Self::HypervWhp => matches!(host, HostPlatform::Windows),
            Self::AppleVirtualization => matches!(host, HostPlatform::Macos),
            Self::Bhyve => matches!(
                host,
                HostPlatform::FreeBsd
                    | HostPlatform::OpenBsd
                    | HostPlatform::NetBsd
                    | HostPlatform::DragonFlyBsd
            ),
        }
    }

    /// Whether backend supports the requested guest architecture.
    pub fn supports_guest_architecture(self, architecture: GuestArchitecture) -> bool {
        match self {
            Self::SoftwareDbt => true,
            // KVM is modeled as the broadest adapter family in UVM contracts.
            Self::Kvm => true,
            Self::HypervWhp => matches!(architecture, GuestArchitecture::X86_64),
            Self::AppleVirtualization => matches!(architecture, GuestArchitecture::Aarch64),
            Self::Bhyve => matches!(architecture, GuestArchitecture::X86_64),
        }
    }
}

/// Runtime states for the host-side VM execution agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmRuntimeState {
    /// Session has been admitted and persisted, but not prepared.
    Registered,
    /// Session has preflight/runtime artifacts prepared.
    Prepared,
    /// Guest process is actively running.
    Running,
    /// Guest process stopped cleanly.
    Stopped,
    /// Session encountered a failure and needs explicit recovery.
    Failed,
    /// Recovery workflow in progress.
    Recovering,
}

impl VmRuntimeState {
    /// Stable state label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Prepared => "prepared",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Recovering => "recovering",
        }
    }
}

/// State machine actions for runtime sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmRuntimeAction {
    /// Prepare launch material.
    Prepare,
    /// Start the guest runtime.
    Start,
    /// Stop the guest runtime.
    Stop,
    /// Mark the session as failed.
    Fail,
    /// Begin recovery workflow.
    BeginRecover,
    /// Complete recovery and return to running state.
    CompleteRecover,
}

/// Validate and apply a runtime state transition.
pub fn transition_state(
    current: VmRuntimeState,
    action: VmRuntimeAction,
) -> Result<VmRuntimeState> {
    use VmRuntimeAction as Action;
    use VmRuntimeState as State;

    let next = match (current, action) {
        (State::Registered, Action::Prepare) => State::Prepared,
        (State::Registered, Action::Start) => State::Running,
        (State::Prepared, Action::Start) => State::Running,
        (State::Running, Action::Stop) => State::Stopped,
        (State::Stopped, Action::Start) => State::Running,
        (State::Registered, Action::Fail) => State::Failed,
        (State::Prepared, Action::Fail) => State::Failed,
        (State::Running, Action::Fail) => State::Failed,
        (State::Stopped, Action::Fail) => State::Failed,
        (State::Failed, Action::BeginRecover) => State::Recovering,
        (State::Recovering, Action::CompleteRecover) => State::Running,
        _ => {
            return Err(PlatformError::conflict(format!(
                "invalid runtime transition {:?} -> {:?}",
                current, action
            )));
        }
    };
    Ok(next)
}

/// CPU pinning policy for vCPU scheduling on host cores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuPinningPolicy {
    /// No strict pinning requirement.
    None,
    /// Pin vCPUs to dedicated host CPUs.
    Dedicated,
    /// Spread vCPUs across host CPUs for fairness.
    Spread,
}

impl CpuPinningPolicy {
    /// Parse a pinning policy from API/config input.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "dedicated" => Ok(Self::Dedicated),
            "spread" => Ok(Self::Spread),
            _ => Err(PlatformError::invalid(
                "cpu pinning policy must be one of none/dedicated/spread",
            )),
        }
    }

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Dedicated => "dedicated",
            Self::Spread => "spread",
        }
    }
}

/// CPU topology specification used during runtime placement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuTopologySpec {
    /// Number of virtual CPU sockets.
    pub sockets: u8,
    /// Number of cores per socket.
    pub cores_per_socket: u8,
    /// Number of threads per core.
    pub threads_per_core: u8,
    /// Pinning policy used by the host runtime.
    pub pinning_policy: CpuPinningPolicy,
}

impl CpuTopologySpec {
    /// Parse a topology profile into an explicit topology specification.
    ///
    /// Supported forms:
    /// - profile names: `balanced`, `latency_optimized`, `throughput_optimized`, `platform_default`
    /// - explicit tuple: `<sockets>x<cores>x<threads>[:<pinning>]` (example: `1x4x1:dedicated`)
    pub fn from_profile(profile: &str, requested_vcpu: u16) -> Result<Self> {
        if requested_vcpu == 0 {
            return Err(PlatformError::invalid("requested_vcpu must be at least 1"));
        }
        let normalized = profile.trim().to_ascii_lowercase();
        if normalized.is_empty() || normalized == "platform_default" || normalized == "balanced" {
            let cores_per_socket = checked_u8_from_u16(requested_vcpu, "requested_vcpu")?;
            return Ok(Self {
                sockets: 1,
                cores_per_socket,
                threads_per_core: 1,
                pinning_policy: CpuPinningPolicy::Spread,
            });
        }
        if normalized == "latency_optimized" {
            let cores_per_socket = checked_u8_from_u16(requested_vcpu, "requested_vcpu")?;
            return Ok(Self {
                sockets: 1,
                cores_per_socket,
                threads_per_core: 1,
                pinning_policy: CpuPinningPolicy::Dedicated,
            });
        }
        if normalized == "throughput_optimized" {
            if requested_vcpu >= 2 && requested_vcpu.is_multiple_of(2) {
                let cores_per_socket =
                    checked_u8_from_u16(requested_vcpu / 2, "requested_vcpu / 2")?;
                return Ok(Self {
                    sockets: 1,
                    cores_per_socket,
                    threads_per_core: 2,
                    pinning_policy: CpuPinningPolicy::Spread,
                });
            }
            let cores_per_socket = checked_u8_from_u16(requested_vcpu, "requested_vcpu")?;
            return Ok(Self {
                sockets: 1,
                cores_per_socket,
                threads_per_core: 1,
                pinning_policy: CpuPinningPolicy::Spread,
            });
        }

        let mut split = normalized.splitn(2, ':');
        let tuple = split
            .next()
            .ok_or_else(|| PlatformError::invalid("cpu topology profile may not be empty"))?;
        let pinning = split
            .next()
            .map(CpuPinningPolicy::parse)
            .transpose()?
            .unwrap_or(CpuPinningPolicy::Spread);
        let tuple_parts = tuple.split('x').collect::<Vec<_>>();
        if tuple_parts.len() != 3 {
            return Err(PlatformError::invalid(
                "cpu topology profile must be one of balanced/latency_optimized/throughput_optimized or `<sockets>x<cores>x<threads>[:<pinning>]`",
            ));
        }
        let sockets = tuple_parts[0].parse::<u8>().map_err(|error| {
            PlatformError::invalid("invalid cpu sockets value").with_detail(error.to_string())
        })?;
        let cores_per_socket = tuple_parts[1].parse::<u8>().map_err(|error| {
            PlatformError::invalid("invalid cpu cores_per_socket value")
                .with_detail(error.to_string())
        })?;
        let threads_per_core = tuple_parts[2].parse::<u8>().map_err(|error| {
            PlatformError::invalid("invalid cpu threads_per_core value")
                .with_detail(error.to_string())
        })?;
        if sockets == 0 || cores_per_socket == 0 || threads_per_core == 0 {
            return Err(PlatformError::invalid(
                "cpu topology values must all be greater than zero",
            ));
        }
        Ok(Self {
            sockets,
            cores_per_socket,
            threads_per_core,
            pinning_policy: pinning,
        })
    }

    /// Compute total vCPU represented by this topology.
    pub fn total_vcpu(&self) -> Result<u16> {
        let total = u32::from(self.sockets)
            .saturating_mul(u32::from(self.cores_per_socket))
            .saturating_mul(u32::from(self.threads_per_core));
        if total == 0 {
            return Err(PlatformError::invalid(
                "cpu topology values must all be greater than zero",
            ));
        }
        if total > u32::from(u16::MAX) {
            return Err(PlatformError::invalid(
                "cpu topology vcpu count exceeds u16 range",
            ));
        }
        Ok(total as u16)
    }
}

/// NUMA placement policy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumaPolicyMode {
    /// No explicit NUMA preference.
    None,
    /// Prefer the first listed node but allow fallback.
    Preferred,
    /// Strictly pin to listed nodes only.
    Strict,
    /// Interleave memory across listed nodes.
    Interleave,
}

impl NumaPolicyMode {
    /// Parse NUMA policy mode from input.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "preferred" => Ok(Self::Preferred),
            "strict" => Ok(Self::Strict),
            "interleave" => Ok(Self::Interleave),
            _ => Err(PlatformError::invalid(
                "numa policy mode must be one of none/preferred/strict/interleave",
            )),
        }
    }

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Preferred => "preferred",
            Self::Strict => "strict",
            Self::Interleave => "interleave",
        }
    }
}

/// NUMA policy specification used by placement admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaPolicySpec {
    /// NUMA policy mode.
    pub mode: NumaPolicyMode,
    /// Explicit node affinity list.
    pub node_affinity: Vec<u8>,
}

impl NumaPolicySpec {
    /// Parse a NUMA policy profile.
    ///
    /// Supported forms:
    /// - profile names: `platform_default`, `preferred_local`, `strict_local`, `interleave_all`
    /// - explicit form: `<mode>:<node_csv>` (example: `strict:0,1`)
    pub fn from_profile(profile: &str, host_numa_nodes: u8) -> Result<Self> {
        if host_numa_nodes == 0 {
            return Err(PlatformError::invalid("host_numa_nodes must be at least 1"));
        }
        let normalized = profile.trim().to_ascii_lowercase();
        if normalized.is_empty()
            || normalized == "platform_default"
            || normalized == "preferred_local"
        {
            return Ok(Self {
                mode: NumaPolicyMode::Preferred,
                node_affinity: vec![0],
            });
        }
        if normalized == "strict_local" {
            return Ok(Self {
                mode: NumaPolicyMode::Strict,
                node_affinity: vec![0],
            });
        }
        if normalized == "interleave_all" {
            return Ok(Self {
                mode: NumaPolicyMode::Interleave,
                node_affinity: (0..host_numa_nodes).collect(),
            });
        }

        let mut split = normalized.splitn(2, ':');
        let mode = NumaPolicyMode::parse(
            split
                .next()
                .ok_or_else(|| PlatformError::invalid("numa profile may not be empty"))?,
        )?;
        let affinity = split.next().unwrap_or_default();
        let mut nodes = Vec::new();
        if !affinity.trim().is_empty() {
            for value in affinity.split(',') {
                let node = value.trim().parse::<u8>().map_err(|error| {
                    PlatformError::invalid("invalid numa node in affinity list")
                        .with_detail(error.to_string())
                })?;
                if node >= host_numa_nodes {
                    return Err(PlatformError::invalid(format!(
                        "numa node {} is outside host range 0..{}",
                        node,
                        host_numa_nodes.saturating_sub(1)
                    )));
                }
                if nodes.contains(&node) {
                    return Err(PlatformError::invalid(format!(
                        "numa affinity list contains duplicate node {}",
                        node
                    )));
                }
                nodes.push(node);
            }
        }
        if mode == NumaPolicyMode::Strict && nodes.is_empty() {
            return Err(PlatformError::invalid(
                "strict NUMA policy requires at least one affinity node",
            ));
        }
        Ok(Self {
            mode,
            node_affinity: nodes,
        })
    }
}

/// Placement request used to evaluate runtime admission against host capacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementRequest {
    /// Requested vCPU.
    pub requested_vcpu: u16,
    /// Requested memory in MiB.
    pub requested_memory_mb: u64,
    /// Host maximum vCPU allowed for a single runtime.
    pub host_max_vcpu: u16,
    /// Host maximum memory in MiB allowed for a single runtime.
    pub host_max_memory_mb: u64,
    /// Number of NUMA nodes exposed by the host capability.
    pub host_numa_nodes: u8,
    /// Requested CPU topology.
    pub cpu_topology: CpuTopologySpec,
    /// Requested NUMA policy.
    pub numa_policy: NumaPolicySpec,
}

/// Placement admission decision and normalized pinning plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementPlan {
    /// Whether admission is allowed.
    pub admitted: bool,
    /// Normalized vCPU value.
    pub normalized_vcpu: u16,
    /// Normalized memory value in MiB.
    pub normalized_memory_mb: u64,
    /// NUMA nodes pinned by policy.
    pub pinned_numa_nodes: Vec<u8>,
    /// Memory distribution aligned with `pinned_numa_nodes`.
    pub per_node_memory_mb: Vec<u64>,
    /// Hard blockers that deny admission.
    pub blockers: Vec<String>,
    /// Soft warnings that do not deny admission.
    pub warnings: Vec<String>,
}

/// Evaluate placement constraints and build a deterministic host plan.
pub fn plan_placement(request: &PlacementRequest) -> Result<PlacementPlan> {
    if request.requested_vcpu == 0 {
        return Err(PlatformError::invalid("requested_vcpu must be at least 1"));
    }
    if request.requested_memory_mb < 256 {
        return Err(PlatformError::invalid(
            "requested_memory_mb must be at least 256 MiB",
        ));
    }
    if request.host_max_vcpu == 0 || request.host_max_memory_mb == 0 || request.host_numa_nodes == 0
    {
        return Err(PlatformError::invalid(
            "host capability maxima and host_numa_nodes must be non-zero",
        ));
    }

    let mut blockers = Vec::new();
    let mut warnings = Vec::new();

    if request.requested_vcpu > request.host_max_vcpu {
        blockers.push(format!(
            "requested_vcpu {} exceeds host max_vcpu {}",
            request.requested_vcpu, request.host_max_vcpu
        ));
    }
    if request.requested_memory_mb > request.host_max_memory_mb {
        blockers.push(format!(
            "requested_memory_mb {} exceeds host max_memory_mb {}",
            request.requested_memory_mb, request.host_max_memory_mb
        ));
    }

    let topology_vcpu = request.cpu_topology.total_vcpu()?;
    if topology_vcpu != request.requested_vcpu {
        blockers.push(format!(
            "cpu topology resolves to {} vcpu but request requires {}",
            topology_vcpu, request.requested_vcpu
        ));
    }

    let mut pinned_numa_nodes = if request.numa_policy.node_affinity.is_empty() {
        match request.numa_policy.mode {
            NumaPolicyMode::Interleave => (0..request.host_numa_nodes).collect::<Vec<_>>(),
            NumaPolicyMode::Strict => Vec::new(),
            _ => vec![0],
        }
    } else {
        request.numa_policy.node_affinity.clone()
    };
    pinned_numa_nodes.sort_unstable();
    if pinned_numa_nodes
        .windows(2)
        .any(|window| window[0] == window[1])
    {
        blockers.push(String::from("numa affinity list contains duplicate nodes"));
    }
    pinned_numa_nodes.dedup();
    for node in &pinned_numa_nodes {
        if *node >= request.host_numa_nodes {
            blockers.push(format!(
                "numa node {} is outside host range 0..{}",
                node,
                request.host_numa_nodes.saturating_sub(1)
            ));
        }
    }
    if request.numa_policy.mode == NumaPolicyMode::Strict && pinned_numa_nodes.is_empty() {
        blockers.push(String::from(
            "strict NUMA policy requires at least one affinity node",
        ));
    }
    if pinned_numa_nodes.is_empty() && request.numa_policy.mode != NumaPolicyMode::Strict {
        pinned_numa_nodes.push(0);
    }

    let per_node_memory_mb = match request.numa_policy.mode {
        NumaPolicyMode::Interleave => {
            let node_count = pinned_numa_nodes.len() as u64;
            let base = request.requested_memory_mb / node_count;
            let remainder = request.requested_memory_mb % node_count;
            (0..node_count)
                .map(|index| base + if index < remainder { 1 } else { 0 })
                .collect::<Vec<_>>()
        }
        _ => {
            let mut distribution = vec![0_u64; pinned_numa_nodes.len()];
            if let Some(first) = distribution.first_mut() {
                *first = request.requested_memory_mb;
            }
            distribution
        }
    };

    if request.cpu_topology.pinning_policy == CpuPinningPolicy::Dedicated
        && request.requested_vcpu.saturating_mul(2) > request.host_max_vcpu
    {
        warnings.push(String::from(
            "dedicated pinning requests more than 50% of host vcpu budget",
        ));
    }
    if request.numa_policy.mode == NumaPolicyMode::Preferred
        && request.requested_memory_mb > request.host_max_memory_mb / 2
    {
        warnings.push(String::from(
            "preferred NUMA policy with large memory may increase remote memory access",
        ));
    }

    Ok(PlacementPlan {
        admitted: blockers.is_empty(),
        normalized_vcpu: request.requested_vcpu,
        normalized_memory_mb: request.requested_memory_mb,
        pinned_numa_nodes,
        per_node_memory_mb,
        blockers,
        warnings,
    })
}

/// Migration strategy class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStrategy {
    /// Stop-and-copy migration.
    Cold,
    /// Live pre-copy migration.
    LivePreCopy,
    /// Live post-copy migration.
    LivePostCopy,
}

impl MigrationStrategy {
    /// Parse a migration-policy or migration-strategy key into a strategy.
    pub fn parse(value: &str) -> Result<Self> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "cold_only" | "cold" => Ok(Self::Cold),
            "best_effort_live" | "strict_live" | "live_precopy" => Ok(Self::LivePreCopy),
            "live_postcopy" => Ok(Self::LivePostCopy),
            _ => MigrationPolicy::parse(&normalized).map(MigrationPolicy::strategy),
        }
    }

    /// Stable strategy key.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cold => "cold",
            Self::LivePreCopy => "live_precopy",
            Self::LivePostCopy => "live_postcopy",
        }
    }
}

/// Migration budget and convergence constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationBudget {
    /// Strategy to use.
    pub strategy: MigrationStrategy,
    /// Maximum tolerated downtime.
    pub max_downtime_ms: u32,
    /// Maximum pre-copy iterations.
    pub max_iterations: u16,
    /// Available network bandwidth for migration stream.
    pub available_bandwidth_mbps: u64,
    /// Estimated dirty page rate during migration.
    pub dirty_page_rate_mbps: u64,
    /// Guest memory size in MiB.
    pub memory_mb: u64,
}

/// Evaluated migration plan result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// Whether migration is currently admissible.
    pub allowed: bool,
    /// Recommended checkpoint kind for this strategy.
    pub recommended_checkpoint_kind: String,
    /// Estimated transfer duration.
    pub estimated_transfer_seconds: u64,
    /// Expected downtime estimate.
    pub expected_downtime_ms: u32,
    /// Hard blockers when migration is denied.
    pub blockers: Vec<String>,
    /// Soft warnings.
    pub warnings: Vec<String>,
}

/// Evaluate migration budget safety and convergence characteristics.
pub fn evaluate_migration_budget(
    backend: HypervisorBackend,
    budget: &MigrationBudget,
) -> Result<MigrationPlan> {
    if budget.available_bandwidth_mbps == 0 {
        return Err(PlatformError::invalid(
            "available_bandwidth_mbps must be greater than zero",
        ));
    }
    if budget.memory_mb == 0 {
        return Err(PlatformError::invalid(
            "memory_mb must be greater than zero",
        ));
    }
    if budget.max_downtime_ms == 0 {
        return Err(PlatformError::invalid(
            "max_downtime_ms must be greater than zero",
        ));
    }
    if budget.max_iterations == 0 {
        return Err(PlatformError::invalid(
            "max_iterations must be greater than zero",
        ));
    }

    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    let memory_megabits = budget.memory_mb.saturating_mul(8);
    let transfer_seconds = ceil_div_u64(memory_megabits, budget.available_bandwidth_mbps).max(1);
    if transfer_seconds > 3_600 {
        warnings.push(String::from(
            "estimated migration transfer duration exceeds one hour",
        ));
    }

    let recommended_checkpoint_kind = match budget.strategy {
        MigrationStrategy::Cold => "crash_consistent",
        MigrationStrategy::LivePreCopy => "live_precopy",
        MigrationStrategy::LivePostCopy => "live_postcopy",
    }
    .to_owned();

    let expected_downtime_ms = match budget.strategy {
        MigrationStrategy::Cold => {
            let estimated = transfer_seconds.saturating_mul(1_000);
            if estimated > u64::from(budget.max_downtime_ms) {
                blockers.push(format!(
                    "cold migration estimated downtime {}ms exceeds max_downtime_ms {}",
                    estimated, budget.max_downtime_ms
                ));
            }
            estimated.min(u64::from(u32::MAX)) as u32
        }
        MigrationStrategy::LivePreCopy => {
            if !backend.supports_live_migration() {
                blockers.push(format!(
                    "backend {} does not support live migration",
                    backend.as_str()
                ));
            }
            if budget.max_iterations < 2 {
                blockers.push(String::from(
                    "live pre-copy requires max_iterations of at least 2",
                ));
            }
            if budget.dirty_page_rate_mbps >= budget.available_bandwidth_mbps {
                blockers.push(String::from(
                    "dirty_page_rate_mbps must be lower than available_bandwidth_mbps for live pre-copy convergence",
                ));
            } else if budget.dirty_page_rate_mbps.saturating_mul(100)
                >= budget.available_bandwidth_mbps.saturating_mul(80)
            {
                warnings.push(String::from(
                    "dirty page rate is close to bandwidth; migration may have longer convergence",
                ));
            }
            let estimate = 75_u32.saturating_add((budget.memory_mb / 256) as u32);
            if estimate > budget.max_downtime_ms {
                blockers.push(format!(
                    "live pre-copy estimated minimum downtime {}ms exceeds max_downtime_ms {}",
                    estimate, budget.max_downtime_ms
                ));
            }
            estimate
        }
        MigrationStrategy::LivePostCopy => {
            if !backend.supports_live_migration() {
                blockers.push(format!(
                    "backend {} does not support live migration",
                    backend.as_str()
                ));
            }
            if budget.dirty_page_rate_mbps > budget.available_bandwidth_mbps {
                warnings.push(String::from(
                    "dirty page rate exceeds bandwidth; post-copy may increase page-fault latency",
                ));
            }
            let estimate = 150_u32;
            if estimate > budget.max_downtime_ms {
                blockers.push(format!(
                    "live post-copy estimated minimum downtime {}ms exceeds max_downtime_ms {}",
                    estimate, budget.max_downtime_ms
                ));
            }
            estimate
        }
    };

    Ok(MigrationPlan {
        allowed: blockers.is_empty(),
        recommended_checkpoint_kind,
        estimated_transfer_seconds: transfer_seconds,
        expected_downtime_ms,
        blockers,
        warnings,
    })
}

fn ceil_div_u64(left: u64, right: u64) -> u64 {
    if right == 0 {
        return 0;
    }
    left.saturating_add(right.saturating_sub(1)) / right
}

fn checked_u8_from_u16(value: u16, field: &'static str) -> Result<u8> {
    u8::try_from(value).map_err(|_| {
        PlatformError::invalid(format!(
            "{field} exceeds maximum supported profile component size ({})",
            u8::MAX
        ))
    })
}

fn normalize_identifier_token(value: &str, field: &'static str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty")));
    }
    if trimmed.len() > 128 {
        return Err(PlatformError::invalid(format!("{field} exceeds 128 bytes")));
    }
    if trimmed.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(format!(
            "{field} may not contain control characters"
        )));
    }
    if trimmed.starts_with('-') {
        return Err(PlatformError::invalid(format!(
            "{field} may not start with '-'"
        )));
    }
    if !trimmed.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
    }) {
        return Err(PlatformError::invalid(format!(
            "{field} may only contain ASCII letters, digits, '-', '_', '.', and ':'"
        )));
    }
    Ok(trimmed.to_owned())
}

fn contains_parent_traversal(value: &str) -> bool {
    value
        .split(['/', '\\'])
        .any(|segment| segment.trim() == "..")
}

fn is_windows_absolute_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

fn is_supported_reference_scheme(scheme: &str) -> bool {
    matches!(scheme, "object" | "file" | "http" | "https")
}

fn normalize_reference(
    value: &str,
    field: &'static str,
    allow_absolute_path: bool,
) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty")));
    }
    if trimmed.len() > 4096 {
        return Err(PlatformError::invalid(format!(
            "{field} exceeds 4096 bytes"
        )));
    }
    if trimmed
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(PlatformError::invalid(format!(
            "{field} may not contain control characters or whitespace"
        )));
    }

    if let Some(separator_index) = trimmed.find("://") {
        let scheme = trimmed[..separator_index].trim().to_ascii_lowercase();
        let remainder = trimmed[(separator_index + 3)..].trim();
        if scheme.is_empty() || remainder.is_empty() {
            return Err(PlatformError::invalid(format!(
                "{field} must include a non-empty URI scheme and authority/path",
            )));
        }
        if !is_supported_reference_scheme(&scheme) {
            return Err(PlatformError::invalid(format!(
                "{field} URI scheme must be one of object/file/http/https",
            )));
        }
        if !scheme.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        }) {
            return Err(PlatformError::invalid(format!(
                "{field} URI scheme may only contain ASCII letters, digits, '+', '-', and '.'"
            )));
        }
        if remainder.ends_with('/') || remainder.ends_with('\\') {
            return Err(PlatformError::invalid(format!(
                "{field} must reference a file object, not a directory",
            )));
        }
        if contains_parent_traversal(remainder) {
            return Err(PlatformError::invalid(format!(
                "{field} may not contain parent traversal segments (`..`)"
            )));
        }
        return Ok(format!("{scheme}://{remainder}"));
    }

    if !allow_absolute_path {
        return Err(PlatformError::invalid(format!(
            "{field} must be a URI with an explicit storage scheme",
        )));
    }
    if !trimmed.starts_with('/') && !is_windows_absolute_path(trimmed) {
        return Err(PlatformError::invalid(format!(
            "{field} must be an absolute path or URI"
        )));
    }
    if trimmed.ends_with('/') || trimmed.ends_with('\\') {
        return Err(PlatformError::invalid(format!(
            "{field} must reference a file path, not a directory",
        )));
    }
    if contains_parent_traversal(trimmed) {
        return Err(PlatformError::invalid(format!(
            "{field} may not contain parent traversal segments (`..`)"
        )));
    }
    Ok(trimmed.to_owned())
}

/// Public wrapper used by higher-level services so launch and storage
/// references are validated consistently across the UVM stack.
pub fn normalize_path_or_uri_reference(value: &str, field: &'static str) -> Result<String> {
    normalize_reference(value, field, true)
}

fn normalize_memory_bitmap_hash(value: &str) -> Result<String> {
    let trimmed = value.trim().to_ascii_lowercase();
    if trimmed.len() < 4 || trimmed.len() > 256 {
        return Err(PlatformError::invalid(
            "memory_bitmap_hash must be between 4 and 256 hex characters",
        ));
    }
    if !trimmed
        .chars()
        .all(|character| character.is_ascii_hexdigit())
    {
        return Err(PlatformError::invalid(
            "memory_bitmap_hash must contain only hex characters",
        ));
    }
    Ok(trimmed)
}

fn validate_firmware_profile(
    firmware_profile: &str,
    guest_architecture: GuestArchitecture,
    require_secure_boot: bool,
) -> Result<String> {
    let normalized = firmware_profile.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("firmware_profile may not be empty"));
    }
    match normalized.as_str() {
        "uefi_secure" | "uefi_standard" | "bios" => {}
        _ => Err(PlatformError::invalid(
            "firmware_profile must be `uefi_secure`, `uefi_standard`, or `bios`",
        ))?,
    }

    if require_secure_boot && normalized != "uefi_secure" {
        return Err(PlatformError::conflict(
            "secure boot requires firmware_profile `uefi_secure`",
        ));
    }
    if guest_architecture == GuestArchitecture::Aarch64 && normalized == "bios" {
        return Err(PlatformError::conflict(
            "firmware_profile `bios` is not compatible with aarch64 guests",
        ));
    }
    Ok(normalized)
}

fn normalize_firmware_artifact_reference(
    backend: HypervisorBackend,
    firmware_artifact: Option<&str>,
) -> Result<Option<String>> {
    let Some(firmware_artifact) = firmware_artifact else {
        return Ok(None);
    };
    if backend != HypervisorBackend::SoftwareDbt {
        return Err(PlatformError::conflict(
            "firmware_artifact is currently supported only for software_dbt launch contracts",
        ));
    }
    Ok(Some(normalize_path_or_uri_reference(
        firmware_artifact,
        "firmware_artifact",
    )?))
}

/// Initial boot device selected for the guest boot flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootDevice {
    /// Boot directly from the primary virtual disk.
    Disk,
    /// Boot from attached CD-ROM or ISO media first.
    Cdrom,
}

impl BootDevice {
    /// Parse a stable boot-device key.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "disk" => Ok(Self::Disk),
            "cdrom" | "iso" => Ok(Self::Cdrom),
            _ => Err(PlatformError::invalid(
                "boot_device must be `disk` or `cdrom`",
            )),
        }
    }

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disk => "disk",
            Self::Cdrom => "cdrom",
        }
    }
}

fn default_boot_device_key() -> String {
    String::from(BootDevice::Disk.as_str())
}

fn validate_boot_media(
    boot_device: &str,
    cdrom_image: Option<&str>,
) -> Result<(BootDevice, Option<String>)> {
    let boot_device = BootDevice::parse(boot_device)?;
    let cdrom_image = cdrom_image
        .map(|value| normalize_path_or_uri_reference(value, "cdrom_image"))
        .transpose()?;
    if boot_device == BootDevice::Cdrom && cdrom_image.is_none() {
        return Err(PlatformError::conflict(
            "boot_device `cdrom` requires a cdrom_image",
        ));
    }
    Ok((boot_device, cdrom_image))
}

/// Launch specification passed to backend command builders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchSpec {
    /// Runtime session identifier.
    pub runtime_session_id: String,
    /// Instance identifier.
    pub instance_id: String,
    /// Guest architecture.
    pub guest_architecture: GuestArchitecture,
    /// vCPU count.
    pub vcpu: u16,
    /// Memory in MiB.
    pub memory_mb: u64,
    /// Whether secure boot is required.
    pub require_secure_boot: bool,
    /// Firmware profile (`uefi_secure`, `uefi_standard`, `bios`).
    pub firmware_profile: String,
    /// Optional explicit firmware artifact path/URI for software-backed launches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware_artifact: Option<String>,
    /// Disk image path/URI.
    pub disk_image: String,
    /// Optional ISO or CD-ROM image path/URI for install media.
    #[serde(default)]
    pub cdrom_image: Option<String>,
    /// Initial boot device (`disk` or `cdrom`).
    #[serde(default = "default_boot_device_key")]
    pub boot_device: String,
}

/// Concrete executable command emitted by a backend adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchCommand {
    /// Executable or supervisor program name.
    pub program: String,
    /// Positional arguments.
    pub args: Vec<String>,
    /// Environment key-values.
    pub env: Vec<(String, String)>,
}

impl LaunchCommand {
    /// Produce a deterministic fingerprint for a launch contract after
    /// validating program, arguments, and environment entries.
    pub fn canonical_digest(&self) -> Result<String> {
        let program = normalize_launch_program(&self.program)?;
        let args = self
            .args
            .iter()
            .map(|value| normalize_launch_argument(value))
            .collect::<Result<Vec<_>>>()?;
        let mut env = self
            .env
            .iter()
            .map(|(key, value)| {
                Ok((
                    normalize_launch_env_key(key)?,
                    normalize_launch_env_value(value)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        env.sort_unstable_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        for window in env.windows(2) {
            if window[0].0 == window[1].0 {
                return Err(PlatformError::invalid(
                    "launch command may not contain duplicate environment keys",
                ));
            }
        }
        let canonical = format!(
            "program={program}|args={}|env={}",
            args.join("\u{1f}"),
            env.iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join("\u{1e}")
        );
        Ok(sha256_hex(canonical.as_bytes()))
    }
}

/// Build a launch command for a backend using the provided spec.
pub fn build_launch_command(
    backend: HypervisorBackend,
    spec: &LaunchSpec,
) -> Result<LaunchCommand> {
    let runtime_session_id =
        normalize_identifier_token(&spec.runtime_session_id, "runtime_session_id")?;
    let instance_id = normalize_identifier_token(&spec.instance_id, "instance_id")?;
    let firmware_artifact =
        normalize_firmware_artifact_reference(backend, spec.firmware_artifact.as_deref())?;
    let disk_image = normalize_path_or_uri_reference(&spec.disk_image, "disk_image")?;
    let (boot_device, cdrom_image) =
        validate_boot_media(&spec.boot_device, spec.cdrom_image.as_deref())?;
    if spec.vcpu == 0 {
        return Err(PlatformError::invalid("vcpu must be at least 1"));
    }
    if spec.memory_mb < 256 {
        return Err(PlatformError::invalid("memory_mb must be at least 256 MiB"));
    }
    if !backend.supports_guest_architecture(spec.guest_architecture) {
        return Err(PlatformError::conflict(format!(
            "backend {} does not support guest architecture {}",
            backend.as_str(),
            spec.guest_architecture.as_str()
        )));
    }
    if spec.require_secure_boot && !backend.supports_secure_boot() {
        return Err(PlatformError::conflict(format!(
            "backend {} does not support secure boot",
            backend.as_str()
        )));
    }

    let firmware_profile = validate_firmware_profile(
        &spec.firmware_profile,
        spec.guest_architecture,
        spec.require_secure_boot,
    )?;
    if backend == HypervisorBackend::AppleVirtualization && firmware_profile == "bios" {
        return Err(PlatformError::conflict(
            "apple virtualization backend does not support BIOS firmware profile",
        ));
    }

    let mut args = vec![
        String::from("--session"),
        runtime_session_id,
        String::from("--instance"),
        instance_id,
        String::from("--arch"),
        spec.guest_architecture.as_str().to_owned(),
        String::from("--vcpu"),
        spec.vcpu.to_string(),
        String::from("--memory-mb"),
        spec.memory_mb.to_string(),
        String::from("--firmware"),
        firmware_profile,
        String::from("--disk"),
        disk_image,
        String::from("--boot-device"),
        String::from(boot_device.as_str()),
    ];
    if let Some(cdrom_image) = cdrom_image {
        args.push(String::from("--cdrom"));
        args.push(cdrom_image);
    }
    if spec.require_secure_boot {
        args.push(String::from("--secure-boot"));
    }

    if backend == HypervisorBackend::SoftwareDbt {
        if let Some(firmware_artifact) = firmware_artifact {
            args.push(String::from("--firmware-artifact"));
            args.push(firmware_artifact);
        }
        args.push(String::from("--runner-mode"));
        args.push(String::from("supervise"));
        args.push(String::from("--heartbeat-interval-ms"));
        args.push(String::from("1000"));
        args.push(String::from("--ingress-http-bind"));
        args.push(String::from("127.0.0.1:0"));
        args.push(String::from("--ingress-tcp-bind"));
        args.push(String::from("127.0.0.1:0"));
        args.push(String::from("--ingress-udp-bind"));
        args.push(String::from("127.0.0.1:0"));
    }

    let program = match backend {
        HypervisorBackend::SoftwareDbt => "uhost-uvm-runner",
        HypervisorBackend::Kvm => "uvm-kvm",
        HypervisorBackend::HypervWhp => "uvm-hyperv",
        HypervisorBackend::AppleVirtualization => "uvm-apple",
        HypervisorBackend::Bhyve => "uvm-bhyve",
    };

    let command = LaunchCommand {
        program: String::from(program),
        args,
        env: vec![
            (String::from("UVM_BACKEND"), String::from(backend.as_str())),
            (
                String::from("UVM_REQUIRE_SECURE_BOOT"),
                if spec.require_secure_boot {
                    String::from("1")
                } else {
                    String::from("0")
                },
            ),
            (
                String::from("UVM_BOOT_DEVICE"),
                String::from(boot_device.as_str()),
            ),
        ],
    };
    let _ = command.canonical_digest()?;
    Ok(command)
}

fn normalize_launch_program(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid("launch program may not be empty"));
    }
    if trimmed.len() > 128 {
        return Err(PlatformError::invalid("launch program exceeds 128 bytes"));
    }
    if trimmed.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "launch program may not contain control characters",
        ));
    }
    if !trimmed.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '/')
    }) {
        return Err(PlatformError::invalid(
            "launch program may only contain ASCII letters, digits, '-', '_', '.', and '/'",
        ));
    }
    Ok(trimmed.to_owned())
}

fn normalize_launch_argument(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid("launch argument may not be empty"));
    }
    if trimmed.len() > 4096 {
        return Err(PlatformError::invalid("launch argument exceeds 4096 bytes"));
    }
    if trimmed.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "launch argument may not contain control characters",
        ));
    }
    Ok(trimmed.to_owned())
}

fn normalize_launch_env_key(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_uppercase();
    if normalized.is_empty() || normalized.len() > 128 {
        return Err(PlatformError::invalid(
            "launch env key must be between 1 and 128 bytes",
        ));
    }
    if !normalized
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err(PlatformError::invalid(
            "launch env key may only include ASCII alphanumeric characters and `_`",
        ));
    }
    Ok(normalized)
}

fn normalize_launch_env_value(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid("launch env value may not be empty"));
    }
    if trimmed.len() > 4096 {
        return Err(PlatformError::invalid(
            "launch env value exceeds 4096 bytes",
        ));
    }
    if trimmed.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "launch env value may not contain control characters",
        ));
    }
    Ok(trimmed.to_owned())
}

/// Deterministic launch idempotency key for retry de-duplication.
pub fn launch_idempotency_key(backend: HypervisorBackend, spec: &LaunchSpec) -> Result<String> {
    let runtime_session_id =
        normalize_identifier_token(&spec.runtime_session_id, "runtime_session_id")?;
    let instance_id = normalize_identifier_token(&spec.instance_id, "instance_id")?;
    let firmware_artifact =
        normalize_firmware_artifact_reference(backend, spec.firmware_artifact.as_deref())?;
    let disk_image = normalize_path_or_uri_reference(&spec.disk_image, "disk_image")?;
    let (boot_device, cdrom_image) =
        validate_boot_media(&spec.boot_device, spec.cdrom_image.as_deref())?;
    let firmware_profile = validate_firmware_profile(
        &spec.firmware_profile,
        spec.guest_architecture,
        spec.require_secure_boot,
    )?;
    if spec.vcpu == 0 {
        return Err(PlatformError::invalid("vcpu must be at least 1"));
    }
    if spec.memory_mb < 256 {
        return Err(PlatformError::invalid("memory_mb must be at least 256 MiB"));
    }
    if !backend.supports_guest_architecture(spec.guest_architecture) {
        return Err(PlatformError::conflict(format!(
            "backend {} does not support guest architecture {}",
            backend.as_str(),
            spec.guest_architecture.as_str()
        )));
    }
    if spec.require_secure_boot && !backend.supports_secure_boot() {
        return Err(PlatformError::conflict(format!(
            "backend {} does not support secure boot",
            backend.as_str()
        )));
    }

    let canonical = format!(
        "launch:v3|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        backend.as_str(),
        runtime_session_id,
        instance_id,
        spec.guest_architecture.as_str(),
        spec.vcpu,
        spec.memory_mb,
        firmware_profile,
        disk_image,
        boot_device.as_str(),
        cdrom_image.unwrap_or_default(),
        firmware_artifact.unwrap_or_default()
    );
    Ok(sha256_hex(canonical.as_bytes()))
}

/// Backend selection request for preflight/admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendSelectionRequest {
    /// Host family.
    pub host: HostPlatform,
    /// Candidate backend list from node capability.
    pub candidates: Vec<HypervisorBackend>,
    /// Guest architecture.
    pub guest_architecture: GuestArchitecture,
    /// Whether guest is an Apple OS family workload.
    pub apple_guest: bool,
    /// Whether live migration is required for admission.
    pub requires_live_migration: bool,
    /// Whether secure boot is mandatory.
    pub require_secure_boot: bool,
}

/// Backend selection result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendSelection {
    /// Selected backend.
    pub backend: HypervisorBackend,
    /// Human-readable reasoning summary.
    pub reason: String,
}

/// Select the safest compatible backend from candidates.
pub fn select_backend(request: &BackendSelectionRequest) -> Result<BackendSelection> {
    if request.candidates.is_empty() {
        return Err(PlatformError::invalid(
            "backend candidate list may not be empty",
        ));
    }
    if request.apple_guest {
        if request.guest_architecture != GuestArchitecture::Aarch64 {
            return Err(PlatformError::conflict(
                "apple guest workloads require aarch64 guest architecture",
            ));
        }
        if !matches!(request.host, HostPlatform::Macos) {
            return Err(PlatformError::conflict(
                "apple guest workloads require macOS host platform",
            ));
        }
        if let Some(backend) = request.candidates.iter().copied().find(|candidate| {
            *candidate == HypervisorBackend::AppleVirtualization
                && candidate.supported_on_host(request.host)
                && candidate.supports_guest_architecture(request.guest_architecture)
        }) {
            if request.requires_live_migration {
                return Err(PlatformError::conflict(
                    "apple guest workloads do not currently support live migration admission",
                ));
            }
            if request.require_secure_boot && !backend.supports_secure_boot() {
                return Err(PlatformError::conflict(
                    "apple guest secure boot requirement cannot be satisfied by selected backend",
                ));
            }
            return Ok(BackendSelection {
                backend,
                reason: String::from(
                    "apple guest selected apple_virtualization backend under legal guardrails",
                ),
            });
        }
        return Err(PlatformError::conflict(
            "apple guest workloads require apple_virtualization backend",
        ));
    }

    let preference = [
        HypervisorBackend::Kvm,
        HypervisorBackend::HypervWhp,
        HypervisorBackend::AppleVirtualization,
        HypervisorBackend::Bhyve,
        HypervisorBackend::SoftwareDbt,
    ];

    for preferred in preference {
        if !request.candidates.contains(&preferred) {
            continue;
        }
        if !preferred.supported_on_host(request.host) {
            continue;
        }
        if !preferred.supports_guest_architecture(request.guest_architecture) {
            continue;
        }
        if request.requires_live_migration && !preferred.supports_live_migration() {
            continue;
        }
        if request.require_secure_boot && !preferred.supports_secure_boot() {
            continue;
        }
        return Ok(BackendSelection {
            backend: preferred,
            reason: format!(
                "selected {} from compatibility preference",
                preferred.as_str()
            ),
        });
    }

    Err(PlatformError::conflict(
        "no compatible backend candidate satisfied admission requirements",
    ))
}

/// Migration envelope versioned for compatibility-safe replication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationEnvelope {
    /// Protocol version.
    pub protocol_version: u16,
    /// Runtime session id.
    pub runtime_session_id: String,
    /// UVM instance id.
    pub instance_id: String,
    /// Source node id.
    pub source_node_id: String,
    /// Target node id.
    pub target_node_id: String,
    /// Checkpoint storage URI.
    pub checkpoint_uri: String,
    /// Memory bitmap hash.
    pub memory_bitmap_hash: String,
    /// Monotonic disk generation.
    pub disk_generation: u64,
    /// Envelope creation timestamp.
    pub created_at: OffsetDateTime,
}

impl MigrationEnvelope {
    /// Deterministic digest used for integrity assertions and idempotency keys.
    pub fn canonical_digest(&self) -> Result<String> {
        if self.protocol_version == 0 {
            return Err(PlatformError::invalid(
                "migration envelope protocol_version must be greater than zero",
            ));
        }
        if self.disk_generation == 0 {
            return Err(PlatformError::invalid(
                "migration envelope disk_generation must be greater than zero",
            ));
        }

        let runtime_session_id =
            normalize_identifier_token(&self.runtime_session_id, "runtime_session_id")?;
        let instance_id = normalize_identifier_token(&self.instance_id, "instance_id")?;
        let source_node_id = normalize_identifier_token(&self.source_node_id, "source_node_id")?;
        let target_node_id = normalize_identifier_token(&self.target_node_id, "target_node_id")?;
        let checkpoint_uri = normalize_reference(&self.checkpoint_uri, "checkpoint_uri", true)?;
        let memory_bitmap_hash = normalize_memory_bitmap_hash(&self.memory_bitmap_hash)?;

        let canonical = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.protocol_version,
            runtime_session_id,
            instance_id,
            source_node_id,
            target_node_id,
            checkpoint_uri,
            memory_bitmap_hash,
            self.disk_generation,
            self.created_at.unix_timestamp_nanos()
        );
        Ok(sha256_hex(canonical.as_bytes()))
    }

    /// Timestamp-independent digest for idempotent retry handling.
    pub fn idempotency_key(&self) -> Result<String> {
        if self.protocol_version == 0 {
            return Err(PlatformError::invalid(
                "migration envelope protocol_version must be greater than zero",
            ));
        }
        if self.disk_generation == 0 {
            return Err(PlatformError::invalid(
                "migration envelope disk_generation must be greater than zero",
            ));
        }

        let runtime_session_id =
            normalize_identifier_token(&self.runtime_session_id, "runtime_session_id")?;
        let instance_id = normalize_identifier_token(&self.instance_id, "instance_id")?;
        let source_node_id = normalize_identifier_token(&self.source_node_id, "source_node_id")?;
        let target_node_id = normalize_identifier_token(&self.target_node_id, "target_node_id")?;
        let checkpoint_uri = normalize_reference(&self.checkpoint_uri, "checkpoint_uri", true)?;
        let memory_bitmap_hash = normalize_memory_bitmap_hash(&self.memory_bitmap_hash)?;

        let canonical = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            self.protocol_version,
            runtime_session_id,
            instance_id,
            source_node_id,
            target_node_id,
            checkpoint_uri,
            memory_bitmap_hash,
            self.disk_generation
        );
        Ok(sha256_hex(canonical.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use time::OffsetDateTime;

    use super::{
        BackendSelectionRequest, BootDevice, CpuPinningPolicy, CpuTopologySpec, GuestArchitecture,
        HostPlatform, HypervisorBackend, LaunchCommand, LaunchSpec, MigrationBudget,
        MigrationEnvelope, MigrationStrategy, NumaPolicyMode, NumaPolicySpec, PlacementRequest,
        VmRuntimeAction, VmRuntimeState, build_launch_command, evaluate_migration_budget,
        launch_idempotency_key, normalize_path_or_uri_reference, plan_placement, select_backend,
        transition_state,
    };

    #[test]
    fn state_machine_rejects_invalid_transition() {
        let error = transition_state(VmRuntimeState::Running, VmRuntimeAction::Prepare)
            .err()
            .unwrap_or_else(|| panic!("expected invalid transition error"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[test]
    fn state_machine_allows_recovery_path() {
        let failed = transition_state(VmRuntimeState::Running, VmRuntimeAction::Fail)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(failed, VmRuntimeState::Failed);
        let recovering = transition_state(failed, VmRuntimeAction::BeginRecover)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(recovering, VmRuntimeState::Recovering);
        let recovered = transition_state(recovering, VmRuntimeAction::CompleteRecover)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(recovered, VmRuntimeState::Running);
    }

    #[test]
    fn host_platform_round_trips_stable_keys() {
        assert_eq!(
            HostPlatform::parse("dragonflybsd")
                .unwrap_or_else(|error| panic!("{error}"))
                .as_str(),
            "dragonflybsd"
        );
        assert_eq!(
            HostPlatform::parse("WINDOWS")
                .unwrap_or_else(|error| panic!("{error}"))
                .as_str(),
            "windows"
        );
    }

    #[test]
    fn apple_guest_requires_macos_host_and_apple_backend() {
        let request = BackendSelectionRequest {
            host: HostPlatform::Linux,
            candidates: vec![HypervisorBackend::Kvm],
            guest_architecture: GuestArchitecture::X86_64,
            apple_guest: true,
            requires_live_migration: false,
            require_secure_boot: true,
        };
        let error = select_backend(&request)
            .err()
            .unwrap_or_else(|| panic!("expected apple legal guardrail failure"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[test]
    fn apple_guest_rejects_live_migration_requirement() {
        let request = BackendSelectionRequest {
            host: HostPlatform::Macos,
            candidates: vec![HypervisorBackend::AppleVirtualization],
            guest_architecture: GuestArchitecture::Aarch64,
            apple_guest: true,
            requires_live_migration: true,
            require_secure_boot: true,
        };
        let error = select_backend(&request)
            .err()
            .unwrap_or_else(|| panic!("expected apple live migration rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[test]
    fn apple_guest_requires_aarch64_architecture() {
        let request = BackendSelectionRequest {
            host: HostPlatform::Macos,
            candidates: vec![HypervisorBackend::AppleVirtualization],
            guest_architecture: GuestArchitecture::X86_64,
            apple_guest: true,
            requires_live_migration: false,
            require_secure_boot: true,
        };
        let error = select_backend(&request)
            .err()
            .unwrap_or_else(|| panic!("expected apple architecture guardrail"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[test]
    fn linux_prefers_kvm() {
        let request = BackendSelectionRequest {
            host: HostPlatform::Linux,
            candidates: vec![HypervisorBackend::HypervWhp, HypervisorBackend::Kvm],
            guest_architecture: GuestArchitecture::X86_64,
            apple_guest: false,
            requires_live_migration: false,
            require_secure_boot: false,
        };
        let selected = select_backend(&request).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(selected.backend, HypervisorBackend::Kvm);
    }

    #[test]
    fn secure_boot_can_fall_back_to_software_backend_when_it_is_the_only_candidate() {
        let request = BackendSelectionRequest {
            host: HostPlatform::Linux,
            candidates: vec![HypervisorBackend::SoftwareDbt],
            guest_architecture: GuestArchitecture::X86_64,
            apple_guest: false,
            requires_live_migration: false,
            require_secure_boot: true,
        };
        let selected = select_backend(&request).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(selected.backend, HypervisorBackend::SoftwareDbt);
    }

    #[test]
    fn windows_aarch64_rejects_x86_only_hyperv_candidate() {
        let request = BackendSelectionRequest {
            host: HostPlatform::Windows,
            candidates: vec![HypervisorBackend::HypervWhp],
            guest_architecture: GuestArchitecture::Aarch64,
            apple_guest: false,
            requires_live_migration: false,
            require_secure_boot: false,
        };
        let error = select_backend(&request)
            .err()
            .unwrap_or_else(|| panic!("expected architecture compatibility rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[test]
    fn launch_command_includes_secure_boot_flag_when_required() {
        let spec = LaunchSpec {
            runtime_session_id: String::from("urs_1"),
            instance_id: String::from("uvi_1"),
            guest_architecture: GuestArchitecture::X86_64,
            vcpu: 4,
            memory_mb: 4096,
            require_secure_boot: true,
            firmware_profile: String::from("uefi_secure"),
            firmware_artifact: None,
            disk_image: String::from("/var/lib/uvm/disk.raw"),
            cdrom_image: None,
            boot_device: String::from(BootDevice::Disk.as_str()),
        };
        let command = build_launch_command(HypervisorBackend::Kvm, &spec)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(command.program, "uvm-kvm");
        assert!(command.args.iter().any(|arg| arg == "--secure-boot"));
    }

    #[test]
    fn software_backend_launch_command_accepts_secure_boot_contract() {
        let spec = LaunchSpec {
            runtime_session_id: String::from("urs_soft_secure_1"),
            instance_id: String::from("uvi_soft_secure_1"),
            guest_architecture: GuestArchitecture::X86_64,
            vcpu: 2,
            memory_mb: 2048,
            require_secure_boot: true,
            firmware_profile: String::from("uefi_secure"),
            firmware_artifact: Some(String::from(
                "file:///var/lib/uhost/firmware/uefi-secure.fd",
            )),
            disk_image: String::from("object://images/linux.raw"),
            cdrom_image: None,
            boot_device: String::from(BootDevice::Disk.as_str()),
        };
        let command = build_launch_command(HypervisorBackend::SoftwareDbt, &spec)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(command.program, "uhost-uvm-runner");
        assert!(command.args.iter().any(|arg| arg == "--secure-boot"));
        assert!(command.args.windows(2).any(|pair| {
            pair[0] == "--firmware-artifact"
                && pair[1] == "file:///var/lib/uhost/firmware/uefi-secure.fd"
        }));
        assert!(
            command
                .env
                .iter()
                .any(|(key, value)| key == "UVM_REQUIRE_SECURE_BOOT" && value == "1")
        );
    }

    #[test]
    fn software_backend_launch_command_targets_runner_binary() {
        let spec = LaunchSpec {
            runtime_session_id: String::from("urs_soft_1"),
            instance_id: String::from("uvi_soft_1"),
            guest_architecture: GuestArchitecture::X86_64,
            vcpu: 2,
            memory_mb: 2048,
            require_secure_boot: false,
            firmware_profile: String::from("uefi_standard"),
            firmware_artifact: None,
            disk_image: String::from("object://images/linux.raw"),
            cdrom_image: None,
            boot_device: String::from(BootDevice::Disk.as_str()),
        };
        let command = build_launch_command(HypervisorBackend::SoftwareDbt, &spec)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(command.program, "uhost-uvm-runner");
        assert!(
            command
                .env
                .iter()
                .any(|(key, value)| key == "UVM_BACKEND" && value == "software_dbt")
        );
        assert!(
            command
                .args
                .windows(2)
                .any(|pair| pair[0] == "--boot-device" && pair[1] == "disk")
        );
        assert!(
            command
                .args
                .windows(2)
                .any(|pair| pair[0] == "--runner-mode" && pair[1] == "supervise")
        );
        assert!(
            command
                .args
                .windows(2)
                .any(|pair| pair[0] == "--heartbeat-interval-ms" && pair[1] == "1000")
        );
        assert!(
            command
                .args
                .windows(2)
                .any(|pair| pair[0] == "--ingress-http-bind" && pair[1] == "127.0.0.1:0")
        );
        assert!(
            command
                .args
                .windows(2)
                .any(|pair| pair[0] == "--ingress-tcp-bind" && pair[1] == "127.0.0.1:0")
        );
        assert!(
            command
                .args
                .windows(2)
                .any(|pair| pair[0] == "--ingress-udp-bind" && pair[1] == "127.0.0.1:0")
        );
    }

    #[test]
    fn launch_command_supports_cdrom_boot_media() {
        let spec = LaunchSpec {
            runtime_session_id: String::from("urs_iso_1"),
            instance_id: String::from("uvi_iso_1"),
            guest_architecture: GuestArchitecture::X86_64,
            vcpu: 2,
            memory_mb: 4096,
            require_secure_boot: false,
            firmware_profile: String::from("bios"),
            firmware_artifact: None,
            disk_image: String::from("object://images/installer-disk.raw"),
            cdrom_image: Some(String::from("file:///isos/ubuntu-26.04.iso")),
            boot_device: String::from(BootDevice::Cdrom.as_str()),
        };
        let command = build_launch_command(HypervisorBackend::SoftwareDbt, &spec)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            command
                .args
                .windows(2)
                .any(|pair| pair[0] == "--cdrom" && pair[1] == "file:///isos/ubuntu-26.04.iso")
        );
        assert!(
            command
                .args
                .windows(2)
                .any(|pair| pair[0] == "--boot-device" && pair[1] == "cdrom")
        );
    }

    #[test]
    fn launch_command_rejects_cdrom_boot_without_image() {
        let spec = LaunchSpec {
            runtime_session_id: String::from("urs_iso_1"),
            instance_id: String::from("uvi_iso_1"),
            guest_architecture: GuestArchitecture::X86_64,
            vcpu: 2,
            memory_mb: 4096,
            require_secure_boot: false,
            firmware_profile: String::from("bios"),
            firmware_artifact: None,
            disk_image: String::from("object://images/installer-disk.raw"),
            cdrom_image: None,
            boot_device: String::from(BootDevice::Cdrom.as_str()),
        };
        let error = build_launch_command(HypervisorBackend::SoftwareDbt, &spec)
            .err()
            .unwrap_or_else(|| panic!("expected cdrom boot conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[test]
    fn launch_command_canonical_digest_is_stable_across_env_order() {
        let left = LaunchCommand {
            program: String::from("uvm-kvm"),
            args: vec![String::from("--session"), String::from("urs_1")],
            env: vec![
                (String::from("UVM_REQUIRE_SECURE_BOOT"), String::from("0")),
                (String::from("UVM_BACKEND"), String::from("kvm")),
            ],
        };
        let right = LaunchCommand {
            program: String::from("uvm-kvm"),
            args: vec![String::from("--session"), String::from("urs_1")],
            env: vec![
                (String::from("UVM_BACKEND"), String::from("kvm")),
                (String::from("UVM_REQUIRE_SECURE_BOOT"), String::from("0")),
            ],
        };
        let left_digest = left
            .canonical_digest()
            .unwrap_or_else(|error| panic!("{error}"));
        let right_digest = right
            .canonical_digest()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(left_digest, right_digest);
    }

    #[test]
    fn launch_command_rejects_duplicate_env_keys() {
        let command = LaunchCommand {
            program: String::from("uvm-kvm"),
            args: vec![String::from("--session"), String::from("urs_1")],
            env: vec![
                (String::from("UVM_BACKEND"), String::from("kvm")),
                (String::from("uvm_backend"), String::from("override")),
            ],
        };
        let error = command
            .canonical_digest()
            .err()
            .unwrap_or_else(|| panic!("expected duplicate env key rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[test]
    fn normalize_path_or_uri_reference_rejects_parent_traversal() {
        let error = normalize_path_or_uri_reference("object://images/../linux.raw", "disk_image")
            .err()
            .unwrap_or_else(|| panic!("expected parent traversal rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[test]
    fn normalize_path_or_uri_reference_rejects_unsupported_scheme() {
        let error = normalize_path_or_uri_reference("ftp://images/linux.raw", "disk_image")
            .err()
            .unwrap_or_else(|| panic!("expected unsupported scheme rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[test]
    fn launch_command_rejects_bios_with_secure_boot() {
        let spec = LaunchSpec {
            runtime_session_id: String::from("urs_1"),
            instance_id: String::from("uvi_1"),
            guest_architecture: GuestArchitecture::X86_64,
            vcpu: 4,
            memory_mb: 4096,
            require_secure_boot: true,
            firmware_profile: String::from("bios"),
            firmware_artifact: None,
            disk_image: String::from("/var/lib/uvm/disk.raw"),
            cdrom_image: None,
            boot_device: String::from(BootDevice::Disk.as_str()),
        };
        let error = build_launch_command(HypervisorBackend::Kvm, &spec)
            .err()
            .unwrap_or_else(|| panic!("expected secure boot firmware conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[test]
    fn launch_command_rejects_non_secure_uefi_when_secure_boot_is_required() {
        let spec = LaunchSpec {
            runtime_session_id: String::from("urs_1"),
            instance_id: String::from("uvi_1"),
            guest_architecture: GuestArchitecture::X86_64,
            vcpu: 4,
            memory_mb: 4096,
            require_secure_boot: true,
            firmware_profile: String::from("uefi_standard"),
            firmware_artifact: None,
            disk_image: String::from("/var/lib/uvm/disk.raw"),
            cdrom_image: None,
            boot_device: String::from(BootDevice::Disk.as_str()),
        };
        let error = build_launch_command(HypervisorBackend::Kvm, &spec)
            .err()
            .unwrap_or_else(|| panic!("expected strict secure-boot firmware conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[test]
    fn launch_command_rejects_bios_for_aarch64_guest() {
        let spec = LaunchSpec {
            runtime_session_id: String::from("urs_1"),
            instance_id: String::from("uvi_1"),
            guest_architecture: GuestArchitecture::Aarch64,
            vcpu: 4,
            memory_mb: 4096,
            require_secure_boot: false,
            firmware_profile: String::from("bios"),
            firmware_artifact: None,
            disk_image: String::from("object://images/linux-arm64.raw"),
            cdrom_image: None,
            boot_device: String::from(BootDevice::Disk.as_str()),
        };
        let error = build_launch_command(HypervisorBackend::Kvm, &spec)
            .err()
            .unwrap_or_else(|| panic!("expected aarch64 firmware rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[test]
    fn launch_command_rejects_backend_guest_architecture_mismatch() {
        let spec = LaunchSpec {
            runtime_session_id: String::from("urs_1"),
            instance_id: String::from("uvi_1"),
            guest_architecture: GuestArchitecture::Aarch64,
            vcpu: 2,
            memory_mb: 2048,
            require_secure_boot: false,
            firmware_profile: String::from("uefi_standard"),
            firmware_artifact: None,
            disk_image: String::from("object://images/linux-arm64.raw"),
            cdrom_image: None,
            boot_device: String::from(BootDevice::Disk.as_str()),
        };
        let error = build_launch_command(HypervisorBackend::HypervWhp, &spec)
            .err()
            .unwrap_or_else(|| panic!("expected backend architecture mismatch"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[test]
    fn launch_command_rejects_relative_disk_path() {
        let spec = LaunchSpec {
            runtime_session_id: String::from("urs_1"),
            instance_id: String::from("uvi_1"),
            guest_architecture: GuestArchitecture::X86_64,
            vcpu: 2,
            memory_mb: 2048,
            require_secure_boot: false,
            firmware_profile: String::from("uefi_standard"),
            firmware_artifact: None,
            disk_image: String::from("relative/path.raw"),
            cdrom_image: None,
            boot_device: String::from(BootDevice::Disk.as_str()),
        };
        let error = build_launch_command(HypervisorBackend::Kvm, &spec)
            .err()
            .unwrap_or_else(|| panic!("expected relative path rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[test]
    fn launch_command_rejects_disk_path_parent_traversal() {
        let spec = LaunchSpec {
            runtime_session_id: String::from("urs_1"),
            instance_id: String::from("uvi_1"),
            guest_architecture: GuestArchitecture::X86_64,
            vcpu: 2,
            memory_mb: 2048,
            require_secure_boot: false,
            firmware_profile: String::from("uefi_standard"),
            firmware_artifact: None,
            disk_image: String::from("/var/lib/uvm/../disk.raw"),
            cdrom_image: None,
            boot_device: String::from(BootDevice::Disk.as_str()),
        };
        let error = build_launch_command(HypervisorBackend::Kvm, &spec)
            .err()
            .unwrap_or_else(|| panic!("expected parent traversal rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[test]
    fn launch_command_normalizes_uri_scheme_and_identifiers() {
        let spec = LaunchSpec {
            runtime_session_id: String::from("  urs_1  "),
            instance_id: String::from("  uvi_1 "),
            guest_architecture: GuestArchitecture::X86_64,
            vcpu: 2,
            memory_mb: 2048,
            require_secure_boot: false,
            firmware_profile: String::from("uefi_standard"),
            firmware_artifact: None,
            disk_image: String::from("OBJECT://images/disk.raw"),
            cdrom_image: None,
            boot_device: String::from(BootDevice::Disk.as_str()),
        };
        let command = build_launch_command(HypervisorBackend::Kvm, &spec)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(command.args.iter().any(|entry| entry == "urs_1"));
        assert!(command.args.iter().any(|entry| entry == "uvi_1"));
        assert!(
            command
                .args
                .iter()
                .any(|entry| entry == "object://images/disk.raw")
        );
    }

    #[test]
    fn launch_idempotency_key_is_stable_for_equivalent_input() {
        let left = launch_idempotency_key(
            HypervisorBackend::Kvm,
            &LaunchSpec {
                runtime_session_id: String::from("  urs_1 "),
                instance_id: String::from(" uvi_1  "),
                guest_architecture: GuestArchitecture::X86_64,
                vcpu: 2,
                memory_mb: 2048,
                require_secure_boot: true,
                firmware_profile: String::from("UEFI_SECURE"),
                firmware_artifact: None,
                disk_image: String::from("OBJECT://images/disk.raw"),
                cdrom_image: None,
                boot_device: String::from(BootDevice::Disk.as_str()),
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let right = launch_idempotency_key(
            HypervisorBackend::Kvm,
            &LaunchSpec {
                runtime_session_id: String::from("urs_1"),
                instance_id: String::from("uvi_1"),
                guest_architecture: GuestArchitecture::X86_64,
                vcpu: 2,
                memory_mb: 2048,
                require_secure_boot: true,
                firmware_profile: String::from("uefi_secure"),
                firmware_artifact: None,
                disk_image: String::from("object://images/disk.raw"),
                cdrom_image: None,
                boot_device: String::from(BootDevice::Disk.as_str()),
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(left, right);
    }

    #[test]
    fn launch_command_rejects_identifier_starting_with_hyphen() {
        let spec = LaunchSpec {
            runtime_session_id: String::from("-urs_1"),
            instance_id: String::from("uvi_1"),
            guest_architecture: GuestArchitecture::X86_64,
            vcpu: 2,
            memory_mb: 2048,
            require_secure_boot: false,
            firmware_profile: String::from("uefi_standard"),
            firmware_artifact: None,
            disk_image: String::from("/var/lib/uvm/disk.raw"),
            cdrom_image: None,
            boot_device: String::from(BootDevice::Disk.as_str()),
        };
        let error = build_launch_command(HypervisorBackend::Kvm, &spec)
            .err()
            .unwrap_or_else(|| panic!("expected invalid identifier rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[test]
    fn canonical_migration_digest_is_stable_for_equal_input() {
        let envelope = MigrationEnvelope {
            protocol_version: 1,
            runtime_session_id: String::from("urs_1"),
            instance_id: String::from("uvi_1"),
            source_node_id: String::from("nod_source"),
            target_node_id: String::from("nod_target"),
            checkpoint_uri: String::from("object://snapshots/uvm.chk"),
            memory_bitmap_hash: String::from("abc123"),
            disk_generation: 42,
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000)
                .unwrap_or_else(|error| panic!("{error}")),
        };
        let left = envelope
            .canonical_digest()
            .unwrap_or_else(|error| panic!("{error}"));
        let right = envelope
            .canonical_digest()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(left, right);
    }

    #[test]
    fn explicit_cpu_topology_profile_is_parsed() {
        let topology = CpuTopologySpec::from_profile("1x4x1:dedicated", 4)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(topology.sockets, 1);
        assert_eq!(topology.cores_per_socket, 4);
        assert_eq!(topology.threads_per_core, 1);
        assert_eq!(topology.pinning_policy, CpuPinningPolicy::Dedicated);
        let total = topology
            .total_vcpu()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(total, 4);
    }

    #[test]
    fn explicit_cpu_topology_profile_rejects_zero_components() {
        let error = CpuTopologySpec::from_profile("1x0x1", 1)
            .err()
            .unwrap_or_else(|| panic!("expected invalid cpu topology"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[test]
    fn profile_topology_rejects_vcpu_exceeding_profile_component_limit() {
        let error = CpuTopologySpec::from_profile("balanced", 300)
            .err()
            .unwrap_or_else(|| panic!("expected vcpu overflow rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[test]
    fn placement_plan_rejects_topology_vcpu_mismatch() {
        let plan = plan_placement(&PlacementRequest {
            requested_vcpu: 6,
            requested_memory_mb: 8192,
            host_max_vcpu: 32,
            host_max_memory_mb: 131_072,
            host_numa_nodes: 2,
            cpu_topology: CpuTopologySpec {
                sockets: 1,
                cores_per_socket: 2,
                threads_per_core: 2,
                pinning_policy: CpuPinningPolicy::Spread,
            },
            numa_policy: NumaPolicySpec {
                mode: NumaPolicyMode::Preferred,
                node_affinity: vec![0],
            },
        })
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!plan.admitted);
        assert!(plan.blockers.iter().any(|entry| entry.contains("topology")));
    }

    #[test]
    fn placement_plan_rejects_duplicate_numa_affinity() {
        let plan = plan_placement(&PlacementRequest {
            requested_vcpu: 4,
            requested_memory_mb: 4096,
            host_max_vcpu: 32,
            host_max_memory_mb: 131_072,
            host_numa_nodes: 2,
            cpu_topology: CpuTopologySpec {
                sockets: 1,
                cores_per_socket: 4,
                threads_per_core: 1,
                pinning_policy: CpuPinningPolicy::Spread,
            },
            numa_policy: NumaPolicySpec {
                mode: NumaPolicyMode::Preferred,
                node_affinity: vec![1, 1],
            },
        })
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!plan.admitted);
        assert!(
            plan.blockers
                .iter()
                .any(|entry| entry.contains("duplicate"))
        );
    }

    #[test]
    fn strict_numa_profile_requires_explicit_affinity() {
        let error = NumaPolicySpec::from_profile("strict:", 2)
            .err()
            .unwrap_or_else(|| panic!("expected strict NUMA validation failure"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[test]
    fn migration_budget_precopy_requires_convergence_margin() {
        let plan = evaluate_migration_budget(
            HypervisorBackend::Kvm,
            &MigrationBudget {
                strategy: MigrationStrategy::LivePreCopy,
                max_downtime_ms: 300,
                max_iterations: 5,
                available_bandwidth_mbps: 800,
                dirty_page_rate_mbps: 900,
                memory_mb: 4096,
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!plan.allowed);
        assert!(
            plan.blockers
                .iter()
                .any(|entry| entry.contains("dirty_page_rate_mbps"))
        );
    }

    #[test]
    fn migration_budget_cold_mode_allows_non_live_backend() {
        let plan = evaluate_migration_budget(
            HypervisorBackend::Bhyve,
            &MigrationBudget {
                strategy: MigrationStrategy::Cold,
                max_downtime_ms: 8_000,
                max_iterations: 1,
                available_bandwidth_mbps: 4_000,
                dirty_page_rate_mbps: 0,
                memory_mb: 1024,
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(plan.allowed);
        assert_eq!(plan.recommended_checkpoint_kind, "crash_consistent");
    }

    #[test]
    fn migration_budget_rejects_cold_mode_when_downtime_budget_is_too_small() {
        let plan = evaluate_migration_budget(
            HypervisorBackend::Kvm,
            &MigrationBudget {
                strategy: MigrationStrategy::Cold,
                max_downtime_ms: 100,
                max_iterations: 1,
                available_bandwidth_mbps: 1_000,
                dirty_page_rate_mbps: 0,
                memory_mb: 4_096,
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!plan.allowed);
        assert!(
            plan.blockers
                .iter()
                .any(|entry| entry.contains("max_downtime_ms"))
        );
    }

    #[test]
    fn numa_profile_interleave_all_maps_to_host_nodes() {
        let policy = NumaPolicySpec::from_profile("interleave_all", 3)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(policy.mode, NumaPolicyMode::Interleave);
        assert_eq!(policy.node_affinity, vec![0, 1, 2]);
    }

    #[test]
    fn canonical_migration_digest_allows_same_source_and_target_for_local_checkpoints() {
        let envelope = MigrationEnvelope {
            protocol_version: 1,
            runtime_session_id: String::from("urs_1"),
            instance_id: String::from("uvi_1"),
            source_node_id: String::from("nod_1"),
            target_node_id: String::from("nod_1"),
            checkpoint_uri: String::from("object://snapshots/uvm.chk"),
            memory_bitmap_hash: String::from("abc123"),
            disk_generation: 42,
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000)
                .unwrap_or_else(|error| panic!("{error}")),
        };
        let digest = envelope
            .canonical_digest()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!digest.is_empty());
    }

    #[test]
    fn canonical_migration_digest_rejects_relative_checkpoint_reference() {
        let envelope = MigrationEnvelope {
            protocol_version: 1,
            runtime_session_id: String::from("urs_1"),
            instance_id: String::from("uvi_1"),
            source_node_id: String::from("nod_source"),
            target_node_id: String::from("nod_target"),
            checkpoint_uri: String::from("checkpoints/c1"),
            memory_bitmap_hash: String::from("abc123"),
            disk_generation: 42,
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000)
                .unwrap_or_else(|error| panic!("{error}")),
        };
        let error = envelope
            .canonical_digest()
            .err()
            .unwrap_or_else(|| panic!("expected checkpoint reference validation failure"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[test]
    fn migration_idempotency_key_ignores_timestamp_changes() {
        let base = MigrationEnvelope {
            protocol_version: 1,
            runtime_session_id: String::from("urs_1"),
            instance_id: String::from("uvi_1"),
            source_node_id: String::from("nod_source"),
            target_node_id: String::from("nod_target"),
            checkpoint_uri: String::from("object://snapshots/uvm.chk"),
            memory_bitmap_hash: String::from("ABC123"),
            disk_generation: 42,
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000)
                .unwrap_or_else(|error| panic!("{error}")),
        };
        let mut next = base.clone();
        next.created_at = OffsetDateTime::from_unix_timestamp(1_800_000_000)
            .unwrap_or_else(|error| panic!("{error}"));

        let left = base
            .idempotency_key()
            .unwrap_or_else(|error| panic!("{error}"));
        let right = next
            .idempotency_key()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(left, right);
    }

    #[test]
    fn canonical_migration_digest_rejects_non_hex_bitmap_hash() {
        let envelope = MigrationEnvelope {
            protocol_version: 1,
            runtime_session_id: String::from("urs_1"),
            instance_id: String::from("uvi_1"),
            source_node_id: String::from("nod_1"),
            target_node_id: String::from("nod_2"),
            checkpoint_uri: String::from("object://snapshots/uvm.chk"),
            memory_bitmap_hash: String::from("hash-value"),
            disk_generation: 42,
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000)
                .unwrap_or_else(|error| panic!("{error}")),
        };
        let error = envelope
            .canonical_digest()
            .err()
            .unwrap_or_else(|| panic!("expected non-hex hash rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[test]
    fn canonical_migration_digest_normalizes_uri_scheme_and_hash_case() {
        let lower = MigrationEnvelope {
            protocol_version: 1,
            runtime_session_id: String::from("urs_1"),
            instance_id: String::from("uvi_1"),
            source_node_id: String::from("nod_source"),
            target_node_id: String::from("nod_target"),
            checkpoint_uri: String::from("object://snapshots/uvm.chk"),
            memory_bitmap_hash: String::from("abc123"),
            disk_generation: 42,
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000)
                .unwrap_or_else(|error| panic!("{error}")),
        };
        let upper = MigrationEnvelope {
            checkpoint_uri: String::from("OBJECT://snapshots/uvm.chk"),
            memory_bitmap_hash: String::from("ABC123"),
            ..lower.clone()
        };
        let lower_digest = lower
            .canonical_digest()
            .unwrap_or_else(|error| panic!("{error}"));
        let upper_digest = upper
            .canonical_digest()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(lower_digest, upper_digest);
    }

    proptest! {
        #[test]
        fn digest_changes_when_disk_generation_changes(disk_generation in 1_u64..10_000_u64) {
            let base = MigrationEnvelope {
                protocol_version: 1,
                runtime_session_id: String::from("urs_1"),
                instance_id: String::from("uvi_1"),
                source_node_id: String::from("nod_source"),
                target_node_id: String::from("nod_target"),
                checkpoint_uri: String::from("object://snapshots/uvm.chk"),
                memory_bitmap_hash: String::from("abc123"),
                disk_generation,
                created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000)
                    .unwrap_or_else(|error| panic!("{error}")),
            };
            let mut next = base.clone();
            next.disk_generation = disk_generation.saturating_add(1);

            let left = base.canonical_digest().unwrap_or_else(|error| panic!("{error}"));
            let right = next.canonical_digest().unwrap_or_else(|error| panic!("{error}"));
            prop_assert_ne!(left, right);
        }
    }
}
