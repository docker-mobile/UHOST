use serde::{Deserialize, Serialize};
use uhost_core::Result;

use crate::{
    CpuPinningPolicy, GuestArchitecture, HypervisorBackend, LaunchCommand, LaunchSpec,
    MachineFamily, MigrationPlan, NumaPolicyMode, PlacementPlan, build_launch_command,
};

/// Execution-class bucket used to tune runtime defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionClass {
    /// Optimize for low tail latency.
    LatencyOptimized,
    /// Balanced default profile.
    Balanced,
    /// Optimize for host density while preserving VM semantics.
    DensityOptimized,
}

impl ExecutionClass {
    /// Parse a stable execution-class key.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "latency_optimized" => Ok(Self::LatencyOptimized),
            "balanced" => Ok(Self::Balanced),
            "density_optimized" => Ok(Self::DensityOptimized),
            _ => Err(uhost_core::PlatformError::invalid(
                "execution class must be one of latency_optimized/balanced/density_optimized",
            )),
        }
    }

    /// Stable string key.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LatencyOptimized => "latency_optimized",
            Self::Balanced => "balanced",
            Self::DensityOptimized => "density_optimized",
        }
    }
}

/// Boot-path tuning used by the runtime adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootPath {
    /// Minimal virtio-first microvm path.
    MicroVm,
    /// General-purpose path with broader compatibility.
    GeneralPurpose,
    /// Apple-native virtualization path.
    AppleVm,
}

impl BootPath {
    /// Parse a stable boot-path key.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "microvm" => Ok(Self::MicroVm),
            "general_purpose" => Ok(Self::GeneralPurpose),
            "apple_vm" => Ok(Self::AppleVm),
            _ => Err(uhost_core::PlatformError::invalid(
                "boot path must be one of microvm/general_purpose/apple_vm",
            )),
        }
    }

    /// Stable string key.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MicroVm => "microvm",
            Self::GeneralPurpose => "general_purpose",
            Self::AppleVm => "apple_vm",
        }
    }
}

/// Memory-backing mode selected for the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryBacking {
    /// Anonymous private pages.
    Anonymous,
    /// Hugepage-backed memory for lower TLB pressure.
    HugePages,
    /// File-backed shared memory region.
    FileBacked,
}

impl MemoryBacking {
    /// Parse a stable memory-backing key.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "anonymous" => Ok(Self::Anonymous),
            "hugepages" => Ok(Self::HugePages),
            "file_backed" => Ok(Self::FileBacked),
            _ => Err(uhost_core::PlatformError::invalid(
                "memory backing must be one of anonymous/hugepages/file_backed",
            )),
        }
    }

    /// Stable string key.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::HugePages => "hugepages",
            Self::FileBacked => "file_backed",
        }
    }
}

/// Device-model shape requested from the runtime adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceModel {
    /// Minimal virtio device set.
    VirtioMinimal,
    /// Balanced virtio device set for broader compatibility.
    VirtioBalanced,
    /// Apple-integrated virtualization device model.
    AppleIntegrated,
}

impl DeviceModel {
    /// Parse a stable device-model key.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "virtio_minimal" => Ok(Self::VirtioMinimal),
            "virtio_balanced" => Ok(Self::VirtioBalanced),
            "apple_integrated" => Ok(Self::AppleIntegrated),
            _ => Err(uhost_core::PlatformError::invalid(
                "device model must be one of virtio_minimal/virtio_balanced/apple_integrated",
            )),
        }
    }

    /// Stable string key.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VirtioMinimal => "virtio_minimal",
            Self::VirtioBalanced => "virtio_balanced",
            Self::AppleIntegrated => "apple_integrated",
        }
    }
}

/// Sandbox hardening layers requested for the runtime process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxLayer {
    /// Syscall filtering.
    Seccomp,
    /// Mount/user/pid/network namespace isolation.
    Namespaces,
    /// Host resource accounting boundary.
    CgroupV2,
    /// Linux capability drop set.
    CapabilityDrop,
    /// Windows job-object isolation.
    JobObject,
    /// macOS seatbelt / containerization boundary.
    Seatbelt,
}

impl SandboxLayer {
    /// Stable string key.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Seccomp => "seccomp",
            Self::Namespaces => "namespaces",
            Self::CgroupV2 => "cgroup_v2",
            Self::CapabilityDrop => "capability_drop",
            Self::JobObject => "job_object",
            Self::Seatbelt => "seatbelt",
        }
    }
}

/// Telemetry streams that must be collected for operational control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryStream {
    /// Lifecycle transition stream.
    Lifecycle,
    /// Heartbeat liveness stream.
    Heartbeat,
    /// Exit/fault stream.
    Exit,
    /// CPU usage stream.
    Cpu,
    /// Memory pressure stream.
    Memory,
    /// Block I/O stream.
    BlockIo,
    /// Network I/O stream.
    NetIo,
}

impl TelemetryStream {
    /// Stable string key.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lifecycle => "lifecycle",
            Self::Heartbeat => "heartbeat",
            Self::Exit => "exit",
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::BlockIo => "block_io",
            Self::NetIo => "net_io",
        }
    }
}

const SOFTWARE_DBT_WORKERS: [&str; 4] = ["supervisor", "core", "block", "net"];

/// Rich UVM execution plan synthesized before runtime registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmExecutionPlan {
    /// Runtime class.
    pub execution_class: String,
    /// Machine-family selection.
    pub machine_family: String,
    /// Boot-path mode.
    pub boot_path: String,
    /// Memory-backing mode.
    pub memory_backing: String,
    /// Device-model selection.
    pub device_model: String,
    /// Requested sandbox layers.
    pub sandbox_layers: Vec<String>,
    /// Required telemetry streams.
    pub telemetry_streams: Vec<String>,
    /// Adapter launch command.
    pub launch: LaunchCommand,
    /// Human-readable notes.
    pub notes: Vec<String>,
}

/// Inputs used to synthesize the concrete runtime execution plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPlanRequest<'a> {
    /// Selected backend.
    pub backend: HypervisorBackend,
    /// Launch spec.
    pub launch_spec: &'a LaunchSpec,
    /// Effective placement plan.
    pub placement: &'a PlacementPlan,
    /// Effective migration plan.
    pub migration_plan: &'a MigrationPlan,
    /// CPU topology used for admission.
    pub cpu_topology: &'a crate::CpuTopologySpec,
    /// NUMA policy used for admission.
    pub numa_policy: &'a crate::NumaPolicySpec,
    /// Isolation profile key from the node service.
    pub isolation_profile: &'a str,
    /// Restart policy key from the node service.
    pub restart_policy: &'a str,
}

/// Build the detailed execution plan that a UVM adapter should honor.
pub fn synthesize_execution_plan(request: &ExecutionPlanRequest<'_>) -> Result<UvmExecutionPlan> {
    let mut launch = build_launch_command(request.backend, request.launch_spec)?;
    let execution_class = if request.cpu_topology.pinning_policy == CpuPinningPolicy::Dedicated {
        ExecutionClass::LatencyOptimized
    } else if request.launch_spec.memory_mb >= 16 * 1024 {
        ExecutionClass::DensityOptimized
    } else {
        ExecutionClass::Balanced
    };
    let boot_path = match request.backend {
        HypervisorBackend::Kvm
            if request.launch_spec.guest_architecture == GuestArchitecture::X86_64 =>
        {
            BootPath::MicroVm
        }
        HypervisorBackend::AppleVirtualization => BootPath::AppleVm,
        _ => BootPath::GeneralPurpose,
    };
    let machine_family = match boot_path {
        BootPath::MicroVm => MachineFamily::MicrovmLinux,
        BootPath::AppleVm => MachineFamily::Aarch64Virt,
        BootPath::GeneralPurpose
            if request.launch_spec.guest_architecture == GuestArchitecture::Aarch64 =>
        {
            MachineFamily::Aarch64Virt
        }
        BootPath::GeneralPurpose => MachineFamily::GeneralPurposePci,
    };
    let memory_backing = if request.backend == HypervisorBackend::Kvm
        && request.launch_spec.memory_mb >= 4 * 1024
        && request.isolation_profile != "container_fallback"
    {
        MemoryBacking::HugePages
    } else if request.backend == HypervisorBackend::SoftwareDbt
        || request.numa_policy.mode == NumaPolicyMode::Interleave
    {
        MemoryBacking::FileBacked
    } else {
        MemoryBacking::Anonymous
    };
    let device_model = match request.backend {
        HypervisorBackend::AppleVirtualization => DeviceModel::AppleIntegrated,
        HypervisorBackend::Kvm if request.launch_spec.vcpu <= 4 => DeviceModel::VirtioMinimal,
        HypervisorBackend::SoftwareDbt => DeviceModel::VirtioBalanced,
        _ => DeviceModel::VirtioBalanced,
    };

    let mut sandbox_layers = match request.backend {
        HypervisorBackend::SoftwareDbt | HypervisorBackend::Kvm | HypervisorBackend::Bhyve => vec![
            SandboxLayer::Seccomp,
            SandboxLayer::Namespaces,
            SandboxLayer::CgroupV2,
            SandboxLayer::CapabilityDrop,
        ],
        HypervisorBackend::HypervWhp => vec![SandboxLayer::JobObject],
        HypervisorBackend::AppleVirtualization => vec![SandboxLayer::Seatbelt],
    };
    sandbox_layers.sort_by_key(|layer| layer.as_str());

    let telemetry_streams = vec![
        TelemetryStream::Lifecycle,
        TelemetryStream::Heartbeat,
        TelemetryStream::Exit,
        TelemetryStream::Cpu,
        TelemetryStream::Memory,
        TelemetryStream::BlockIo,
        TelemetryStream::NetIo,
    ];

    launch.args.push(String::from("--boot-path"));
    launch.args.push(String::from(boot_path.as_str()));
    launch.args.push(String::from("--device-model"));
    launch.args.push(String::from(device_model.as_str()));
    launch.args.push(String::from("--memory-backing"));
    launch.args.push(String::from(memory_backing.as_str()));
    launch.args.push(String::from("--execution-class"));
    launch.args.push(String::from(execution_class.as_str()));
    launch.args.push(String::from("--machine-family"));
    launch.args.push(String::from(machine_family.as_str()));
    launch.args.push(String::from("--restart-policy"));
    launch.args.push(String::from(request.restart_policy));
    launch.args.push(String::from("--migration-kind"));
    launch
        .args
        .push(request.migration_plan.recommended_checkpoint_kind.clone());
    for node in &request.placement.pinned_numa_nodes {
        launch.args.push(String::from("--numa-node"));
        launch.args.push(node.to_string());
    }
    for stream in &telemetry_streams {
        launch.args.push(String::from("--telemetry"));
        launch.args.push(String::from(stream.as_str()));
    }
    launch.env.push((
        String::from("UVM_EXECUTION_CLASS"),
        String::from(execution_class.as_str()),
    ));
    launch.env.push((
        String::from("UVM_MACHINE_FAMILY"),
        String::from(machine_family.as_str()),
    ));
    launch.env.push((
        String::from("UVM_BOOT_PATH"),
        String::from(boot_path.as_str()),
    ));
    launch.env.push((
        String::from("UVM_DEVICE_MODEL"),
        String::from(device_model.as_str()),
    ));
    launch.env.push((
        String::from("UVM_MEMORY_BACKING"),
        String::from(memory_backing.as_str()),
    ));
    launch.env.push((
        String::from("UVM_NUMA_NODE_COUNT"),
        request.placement.pinned_numa_nodes.len().to_string(),
    ));
    if request.backend == HypervisorBackend::SoftwareDbt {
        launch.env.push((
            String::from("UVM_SANDBOX_LAYERS"),
            sandbox_layers
                .iter()
                .map(|layer| layer.as_str())
                .collect::<Vec<_>>()
                .join(","),
        ));
        launch.env.push((
            String::from("UVM_SOFTVM_WORKERS"),
            SOFTWARE_DBT_WORKERS.as_slice().join(","),
        ));
    }

    let mut notes = Vec::new();
    if request.migration_plan.expected_downtime_ms <= 250 {
        notes.push(String::from(
            "migration target qualifies for aggressive cutover budget",
        ));
    }
    if request.launch_spec.require_secure_boot {
        notes.push(String::from(
            "secure boot remains enforced through firmware and launch policy",
        ));
    }
    if request.placement.pinned_numa_nodes.len() > 1 {
        notes.push(String::from(
            "runtime spans multiple NUMA nodes and requires remote-memory telemetry",
        ));
    }
    if request.backend == HypervisorBackend::SoftwareDbt {
        notes.push(String::from(
            "software_dbt backend selected; superiority claims remain evidence-gated until direct benchmark evidence exists",
        ));
    }

    Ok(UvmExecutionPlan {
        execution_class: String::from(execution_class.as_str()),
        machine_family: String::from(machine_family.as_str()),
        boot_path: String::from(boot_path.as_str()),
        memory_backing: String::from(memory_backing.as_str()),
        device_model: String::from(device_model.as_str()),
        sandbox_layers: sandbox_layers
            .into_iter()
            .map(|layer| String::from(layer.as_str()))
            .collect(),
        telemetry_streams: telemetry_streams
            .into_iter()
            .map(|stream| String::from(stream.as_str()))
            .collect(),
        launch,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::{ExecutionPlanRequest, synthesize_execution_plan};
    use crate::{
        BootDevice, CpuPinningPolicy, CpuTopologySpec, GuestArchitecture, HypervisorBackend,
        LaunchSpec, MigrationPlan, NumaPolicyMode, NumaPolicySpec, PlacementPlan,
    };

    #[test]
    fn synthesize_execution_plan_enriches_launch_contract() {
        let request = ExecutionPlanRequest {
            backend: HypervisorBackend::Kvm,
            launch_spec: &LaunchSpec {
                runtime_session_id: String::from("urs_1"),
                instance_id: String::from("uvi_1"),
                guest_architecture: GuestArchitecture::X86_64,
                vcpu: 4,
                memory_mb: 8192,
                require_secure_boot: true,
                firmware_profile: String::from("uefi_secure"),
                firmware_artifact: None,
                disk_image: String::from("object://images/linux.raw"),
                cdrom_image: None,
                boot_device: String::from(BootDevice::Disk.as_str()),
            },
            placement: &PlacementPlan {
                admitted: true,
                normalized_vcpu: 4,
                normalized_memory_mb: 8192,
                pinned_numa_nodes: vec![0],
                per_node_memory_mb: vec![8192],
                blockers: Vec::new(),
                warnings: Vec::new(),
            },
            migration_plan: &MigrationPlan {
                allowed: true,
                recommended_checkpoint_kind: String::from("live_precopy"),
                estimated_transfer_seconds: 4,
                expected_downtime_ms: 140,
                blockers: Vec::new(),
                warnings: Vec::new(),
            },
            cpu_topology: &CpuTopologySpec {
                sockets: 1,
                cores_per_socket: 4,
                threads_per_core: 1,
                pinning_policy: CpuPinningPolicy::Dedicated,
            },
            numa_policy: &NumaPolicySpec {
                mode: NumaPolicyMode::Preferred,
                node_affinity: vec![0],
            },
            isolation_profile: "cgroup_v2",
            restart_policy: "always",
        };
        let plan = synthesize_execution_plan(&request).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(plan.execution_class, "latency_optimized");
        assert_eq!(plan.machine_family, "microvm_linux");
        assert_eq!(plan.boot_path, "microvm");
        assert_eq!(plan.memory_backing, "hugepages");
        assert!(
            plan.launch
                .args
                .windows(2)
                .any(|pair| pair[0] == "--device-model" && pair[1] == "virtio_minimal")
        );
        assert!(
            plan.launch
                .env
                .iter()
                .any(|(key, value)| key == "UVM_EXECUTION_CLASS" && value == "latency_optimized")
        );
        assert!(
            plan.launch
                .env
                .iter()
                .any(|(key, value)| key == "UVM_MACHINE_FAMILY" && value == "microvm_linux")
        );
    }

    #[test]
    fn software_dbt_execution_plan_exports_runner_worker_and_sandbox_contract() {
        let request = ExecutionPlanRequest {
            backend: HypervisorBackend::SoftwareDbt,
            launch_spec: &LaunchSpec {
                runtime_session_id: String::from("urs_softvm_1"),
                instance_id: String::from("uvi_softvm_1"),
                guest_architecture: GuestArchitecture::X86_64,
                vcpu: 2,
                memory_mb: 4096,
                require_secure_boot: false,
                firmware_profile: String::from("uefi_standard"),
                firmware_artifact: Some(String::from(
                    "file:///var/lib/uhost/firmware/uefi-standard.fd",
                )),
                disk_image: String::from("object://images/linux.raw"),
                cdrom_image: None,
                boot_device: String::from(BootDevice::Disk.as_str()),
            },
            placement: &PlacementPlan {
                admitted: true,
                normalized_vcpu: 2,
                normalized_memory_mb: 4096,
                pinned_numa_nodes: vec![0],
                per_node_memory_mb: vec![4096],
                blockers: Vec::new(),
                warnings: Vec::new(),
            },
            migration_plan: &MigrationPlan {
                allowed: true,
                recommended_checkpoint_kind: String::from("crash_consistent"),
                estimated_transfer_seconds: 8,
                expected_downtime_ms: 800,
                blockers: Vec::new(),
                warnings: Vec::new(),
            },
            cpu_topology: &CpuTopologySpec {
                sockets: 1,
                cores_per_socket: 2,
                threads_per_core: 1,
                pinning_policy: CpuPinningPolicy::Spread,
            },
            numa_policy: &NumaPolicySpec {
                mode: NumaPolicyMode::Preferred,
                node_affinity: vec![0],
            },
            isolation_profile: "cgroup_v2",
            restart_policy: "on-failure",
        };
        let plan = synthesize_execution_plan(&request).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            plan.sandbox_layers,
            vec![
                String::from("capability_drop"),
                String::from("cgroup_v2"),
                String::from("namespaces"),
                String::from("seccomp"),
            ]
        );
        assert!(
            plan.launch
                .env
                .iter()
                .any(|(key, value)| key == "UVM_SANDBOX_LAYERS"
                    && value == "capability_drop,cgroup_v2,namespaces,seccomp")
        );
        assert!(plan.launch.env.iter().any(
            |(key, value)| key == "UVM_SOFTVM_WORKERS" && value == "supervisor,core,block,net"
        ));
        assert!(plan.launch.args.windows(2).any(|pair| {
            pair[0] == "--firmware-artifact"
                && pair[1] == "file:///var/lib/uhost/firmware/uefi-standard.fd"
        }));
    }
}
