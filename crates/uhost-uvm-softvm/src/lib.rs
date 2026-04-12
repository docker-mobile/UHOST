//! Minimal software-backed UVM runtime skeleton primitives.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    net::{Shutdown, TcpStream, ToSocketAddrs, UdpSocket},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use uhost_core::{PlatformError, Result, sha256_hex};
use uhost_uvm::{ExecutionClass, HypervisorBackend};
use uhost_uvm_machine::{
    MachineDevice, MachineMemoryRegion, MachineSpec, MachineTopology, MemoryLayout,
};

const MAX_BOOT_ARTIFACT_PREVIEW_BYTES: usize = 64 * 1024;
const DEFAULT_BLOCK_SIZE_BYTES: u32 = 4096;
const GUEST_PROGRAM_ENTRY_STRIDE: u64 = 0x100;
const GUEST_RAM_DATA_BASE: u64 = 0x0400_0000;
const SOFT_VM_GUEST_PAGE_BYTES: u64 = 0x1000;
const DIRECT_KERNEL_IMAGE_GUEST_OFFSET_BYTES: u64 = 0x8000;
const DIRECT_KERNEL_BOOT_PARAMS_GUEST_ADDRESS: u64 = 0x0001_0000;
const DIRECT_KERNEL_CMDLINE_GUEST_ADDRESS: u64 = 0x0001_1000;
const UART_CONSOLE_MMIO_BASE: u64 = 0x1000_0000;
const VIRTIO_CONSOLE_MMIO_BASE: u64 = 0x1003_0000;

const ISA_OPCODE_MOV_IMM64: u8 = 0x10;
const ISA_OPCODE_NATIVE_CALL: u8 = 0x11;
const ISA_OPCODE_CALL_ABS64: u8 = 0x12;
const ISA_OPCODE_RET: u8 = 0x13;
const ISA_OPCODE_MMIO_WRITE64: u8 = 0x14;
const ISA_OPCODE_MMIO_READ64: u8 = 0x15;
const ISA_OPCODE_HALT: u8 = 0xff;

const ISA_REGISTER_ARG0: u8 = 0;
const ISA_REGISTER_ARG1: u8 = 1;
const ISA_REGISTER_ARG2: u8 = 2;
const ISA_REGISTER_ARG3: u8 = 3;

const NATIVE_CALL_FIRMWARE_DISPATCH: u8 = 0x01;
const NATIVE_CALL_INSTALL_MEDIA_PROBE: u8 = 0x02;
const NATIVE_CALL_BOOT_DEVICE_TRANSFER: u8 = 0x03;
const NATIVE_CALL_USERSPACE_CONTROL: u8 = 0x04;
const NATIVE_CALL_BOOT_SERVICE_ROUTE: u8 = 0x05;
const NATIVE_CALL_DIRECT_KERNEL_ENTRY: u8 = 0x06;

const NATIVE_CALL_GUEST_UNAME: u8 = 0x40;
const NATIVE_CALL_GUEST_SYSTEM_STATE: u8 = 0x41;
const NATIVE_CALL_GUEST_SYSTEMCTL_STATUS: u8 = 0x42;
const NATIVE_CALL_GUEST_CAT: u8 = 0x43;
const NATIVE_CALL_GUEST_ECHO_REDIRECT: u8 = 0x44;
const NATIVE_CALL_GUEST_TOUCH: u8 = 0x45;
const NATIVE_CALL_GUEST_LS: u8 = 0x46;
const NATIVE_CALL_GUEST_SHA256SUM: u8 = 0x47;
const NATIVE_CALL_GUEST_UNIXBENCH: u8 = 0x48;
const NATIVE_CALL_GUEST_UNSUPPORTED: u8 = 0x49;
const NATIVE_CALL_GUEST_HTTP_FETCH: u8 = 0x4a;
const NATIVE_CALL_GUEST_TCP_CONNECT: u8 = 0x4b;
const NATIVE_CALL_GUEST_DNS_LOOKUP: u8 = 0x4c;
const NATIVE_CALL_GUEST_UDP_EXCHANGE: u8 = 0x4d;
const NATIVE_CALL_GUEST_SERVICE_ROUTE: u8 = 0x51;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuestKernelOperationDescriptor {
    operation: u8,
    kind: u8,
    route: u8,
}

impl GuestKernelOperationDescriptor {
    fn operation_name(self) -> &'static str {
        native_call_name(self.operation)
    }
}

const GUEST_KERNEL_SERVICE_VERSION: u8 = 1;
const GUEST_KERNEL_SERVICE_KIND_READ_ONLY: u8 = 1;
const GUEST_KERNEL_SERVICE_KIND_MUTATION: u8 = 2;
const GUEST_KERNEL_SERVICE_KIND_INDEX: u8 = 3;
const GUEST_KERNEL_SERVICE_KIND_BENCHMARK: u8 = 4;
const GUEST_KERNEL_SERVICE_KIND_ERROR: u8 = 5;
const GUEST_KERNEL_SERVICE_KIND_NETWORK: u8 = 6;

const GUEST_KERNEL_ROUTE_FIXED_UNAME: u8 = 1;
const GUEST_KERNEL_ROUTE_FIXED_SYSTEM_STATE: u8 = 2;
const GUEST_KERNEL_ROUTE_SERVICE_STATUS: u8 = 3;
const GUEST_KERNEL_ROUTE_FILE_READ: u8 = 4;
const GUEST_KERNEL_ROUTE_FILE_WRITE: u8 = 5;
const GUEST_KERNEL_ROUTE_FILE_TOUCH: u8 = 6;
const GUEST_KERNEL_ROUTE_DIRECTORY_INDEX: u8 = 7;
const GUEST_KERNEL_ROUTE_SHA256_INDEX: u8 = 8;
const GUEST_KERNEL_ROUTE_UNIXBENCH: u8 = 9;
const GUEST_KERNEL_ROUTE_ERROR: u8 = 10;
const GUEST_KERNEL_ROUTE_HTTP_FETCH: u8 = 11;
const GUEST_KERNEL_ROUTE_TCP_CONNECT: u8 = 12;
const GUEST_KERNEL_ROUTE_DNS_LOOKUP: u8 = 13;
const GUEST_KERNEL_ROUTE_UDP_EXCHANGE: u8 = 14;

const GUEST_EGRESS_TRANSPORT: &str = "guest_owned_tcp_udp_http_https_nat_v1";
const GUEST_EGRESS_USER_AGENT: &str = "UHost-SoftVm-GuestControl/0.1";
const GUEST_EGRESS_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_GUEST_EGRESS_BODY_BYTES: usize = 256 * 1024;
const MAX_GUEST_TCP_PAYLOAD_BYTES: usize = 64 * 1024;
const GUEST_INGRESS_TRANSPORT: &str = "guest_owned_tcp_udp_http_nat_v1";
const GUEST_INGRESS_WEB_ROOT: &str = "/var/www";
const GUEST_INGRESS_TCP_DEFAULT_SERVICE: &str = "default";
const GUEST_INGRESS_UDP_DEFAULT_SERVICE: &str = "default";
const GUEST_INGRESS_DEFAULT_HOST_BIND: &str = "127.0.0.1:0";
const GUEST_NETWORK_MODE: &str = "guest_owned_usernet_nat";
const GUEST_NETWORK_PRIMARY_INTERFACE: &str = "eth0";
const GUEST_NETWORK_GUEST_IPV4: &str = "10.0.2.15";
const GUEST_NETWORK_GUEST_CIDR: &str = "10.0.2.15/24";
const GUEST_NETWORK_GATEWAY_IPV4: &str = "10.0.2.2";
const GUEST_NETWORK_DNS_IPV4: &str = "10.0.2.3";

const OPCODE_FIRMWARE_DISPATCH: u8 = 0x01;
const OPCODE_INSTALL_MEDIA_PROBE: u8 = 0x02;
const OPCODE_BOOT_DEVICE_TRANSFER: u8 = 0x03;
const OPCODE_USERSPACE_CONTROL: u8 = 0x04;
const OPCODE_BOOT_SERVICE_ROUTE: u8 = 0x05;
const OPCODE_DIRECT_KERNEL_ENTRY: u8 = 0x06;

const OPCODE_GUEST_UNAME: u8 = 0x40;
const OPCODE_GUEST_SYSTEM_STATE: u8 = 0x41;
const OPCODE_GUEST_SYSTEMCTL_STATUS: u8 = 0x42;
const OPCODE_GUEST_CAT: u8 = 0x43;
const OPCODE_GUEST_ECHO_REDIRECT: u8 = 0x44;
const OPCODE_GUEST_TOUCH: u8 = 0x45;
const OPCODE_GUEST_LS: u8 = 0x46;
const OPCODE_GUEST_SHA256SUM: u8 = 0x47;
const OPCODE_GUEST_UNIXBENCH: u8 = 0x48;
const OPCODE_GUEST_UNSUPPORTED: u8 = 0x49;
const OPCODE_GUEST_HTTP_FETCH: u8 = 0x4a;
const OPCODE_GUEST_TCP_CONNECT: u8 = 0x4b;
const OPCODE_GUEST_DNS_LOOKUP: u8 = 0x4c;
const OPCODE_GUEST_UDP_EXCHANGE: u8 = 0x4d;
const OPCODE_GUEST_SERVICE_ROUTE: u8 = 0x51;
const OPCODE_HALT: u8 = ISA_OPCODE_HALT;

const GUEST_KERNEL_SERVICE_DESCRIPTOR_BYTES: usize = 11;
const BOOT_SERVICE_VERSION: u8 = 1;
const BOOT_SERVICE_DESCRIPTOR_BYTES: usize = 9;
const BLOCK_CONTROL_COMMAND_PROBE_MEDIA: u64 = 1;
const BLOCK_CONTROL_ROLE_PRIMARY_DISK: u64 = 1;
const BLOCK_CONTROL_ROLE_INSTALL_MEDIA: u64 = 2;
const DEVICE_MMIO_STATUS_OFFSET: u64 = 0x0008;
const DEVICE_MMIO_QUEUE_CONTROL_OFFSET: u64 = 0x0010;
const DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET: u64 = 0x0018;
const DEVICE_MMIO_METADATA_OFFSET: u64 = 0x0020;

const DEVICE_INTERRUPT_CONTROL_ACK: u64 = 1;
const DEVICE_INTERRUPT_CONTROL_MASK: u64 = 2;
const DEVICE_INTERRUPT_CONTROL_UNMASK: u64 = 3;

const DEVICE_INTERRUPT_STATE_PENDING: u64 = 1 << 0;
const DEVICE_INTERRUPT_STATE_MASKED: u64 = 1 << 1;
const DEVICE_INTERRUPT_STATE_LATCHED: u64 = 1 << 2;

fn block_control_role_name(role_code: u64) -> Option<&'static str> {
    match role_code {
        BLOCK_CONTROL_ROLE_PRIMARY_DISK => Some("primary_disk"),
        BLOCK_CONTROL_ROLE_INSTALL_MEDIA => Some("install_media"),
        _ => None,
    }
}

fn block_control_role_code(role: &str) -> Option<u64> {
    match role {
        "primary_disk" => Some(BLOCK_CONTROL_ROLE_PRIMARY_DISK),
        "install_media" => Some(BLOCK_CONTROL_ROLE_INSTALL_MEDIA),
        _ => None,
    }
}

fn direct_kernel_boot(spec: &SoftVmRuntimeSpec) -> bool {
    spec.machine.boot.medium == "direct_kernel"
}

fn boot_artifact_role(spec: &SoftVmRuntimeSpec) -> &'static str {
    if direct_kernel_boot(spec) {
        "kernel"
    } else {
        "firmware"
    }
}

fn boot_stage_prefix(spec: &SoftVmRuntimeSpec) -> &'static str {
    if direct_kernel_boot(spec) {
        "direct_kernel"
    } else {
        "firmware"
    }
}

fn boot_code_region_name(spec: &SoftVmRuntimeSpec) -> &'static str {
    if direct_kernel_boot(spec) {
        "direct_kernel_image"
    } else {
        "firmware"
    }
}

fn boot_artifact_display_name(source: &str) -> String {
    if let Some(path) = maybe_local_boot_artifact_path(source) {
        return path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string_lossy().into_owned());
    }
    source.trim().to_owned()
}

fn padded_le_u64(bytes: &[u8]) -> u64 {
    let mut padded = [0u8; 8];
    let copy_len = bytes.len().min(padded.len());
    padded[..copy_len].copy_from_slice(&bytes[..copy_len]);
    u64::from_le_bytes(padded)
}

fn saturating_u64_len(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn packed_u32_pair(low: u64, high: u64) -> u64 {
    (low & u64::from(u32::MAX)) | ((high & u64::from(u32::MAX)) << 32)
}

fn mmio_offset(region: &SoftVmMmioRegion, guest_physical_address: u64) -> u64 {
    guest_physical_address.saturating_sub(region.guest_physical_base)
}

fn direct_kernel_command_line(spec: &SoftVmRuntimeSpec) -> String {
    format!(
        "console=ttyS0 root=/dev/vda rw panic=-1 uhost.execution_class={} uhost.machine_family={} uhost.guest_arch={}",
        spec.execution_class, spec.machine.machine_family, spec.machine.guest_architecture
    )
}

fn direct_kernel_boot_params_manifest(
    spec: &SoftVmRuntimeSpec,
    kernel_source: &str,
    kernel_entry_guest_address: u64,
    kernel_byte_len: u64,
    preview_byte_len: u64,
    command_line_guest_address: u64,
    command_line_byte_len: u64,
) -> String {
    format!(
        concat!(
            "boot_path=microvm\n",
            "machine_family={}\n",
            "guest_architecture={}\n",
            "kernel={}\n",
            "kernel_entry=0x{:x}\n",
            "kernel_bytes={}\n",
            "kernel_preview_bytes={}\n",
            "cmdline_addr=0x{:x}\n",
            "cmdline_len={}\n",
            "boot_device={}\n",
        ),
        spec.machine.machine_family,
        spec.machine.guest_architecture,
        boot_artifact_display_name(kernel_source),
        kernel_entry_guest_address,
        kernel_byte_len,
        preview_byte_len,
        command_line_guest_address,
        command_line_byte_len,
        spec.machine.boot.primary_boot_device,
    )
}

fn softvm_memory_region_from_machine_region(region: &MachineMemoryRegion) -> SoftVmMemoryRegion {
    SoftVmMemoryRegion {
        name: region.name.clone(),
        guest_physical_base: region.guest_physical_base,
        byte_len: region.byte_len,
        writable: region.writable,
    }
}

fn softvm_mmio_region_from_machine_device(device: &MachineDevice) -> SoftVmMmioRegion {
    SoftVmMmioRegion {
        name: device.name.clone(),
        guest_physical_base: device.guest_physical_base,
        byte_len: device.byte_len,
        read_dispatch: device.read_dispatch.clone(),
        write_dispatch: device.write_dispatch.clone(),
    }
}

fn machine_interrupt_vector(topology: &MachineTopology, source: &str) -> Result<u8> {
    topology
        .interrupt_for_source(source)
        .map(|interrupt| interrupt.vector)
        .ok_or_else(|| {
            PlatformError::conflict(format!(
                "machine topology is missing interrupt route for `{source}`"
            ))
        })
}

fn device_loop_shape(device_kind: &str) -> Option<(&'static str, &'static [&'static str])> {
    match device_kind {
        "block_control" => Some(("block_control", &["requests", "responses"])),
        "console" => Some(("serial", &["rx", "tx"])),
        "timer" => Some(("timer", &["events"])),
        "virtio_console" => Some(("virtio_console", &["rx", "tx"])),
        "virtio_rng" => Some(("virtio_rng", &["entropy"])),
        "virtio_net" => Some(("virtio_net", &["rx", "tx"])),
        _ => None,
    }
}

fn softvm_device_loop_from_machine_device(
    topology: &MachineTopology,
    device: &MachineDevice,
) -> Result<Option<SoftVmDeviceLoop>> {
    let Some((device_kind, queue_names)) = device_loop_shape(device.kind.as_str()) else {
        return Ok(None);
    };
    let interrupt_source = device.irq_source.as_deref().unwrap_or(device.name.as_str());
    let interrupt_vector = machine_interrupt_vector(topology, interrupt_source)?;
    Ok(Some(SoftVmDeviceLoop::new(
        device.name.clone(),
        device.name.clone(),
        device_kind,
        interrupt_vector,
        queue_names,
    )))
}

fn softvm_device_loops(topology: &MachineTopology) -> Result<Vec<SoftVmDeviceLoop>> {
    let mut loops = Vec::new();
    for device in &topology.devices {
        if let Some(device_loop) = softvm_device_loop_from_machine_device(topology, device)? {
            loops.push(device_loop);
        }
    }
    Ok(loops)
}

fn guest_program_entry_base(
    topology: &MachineTopology,
    reset_vector: u64,
    offset: u64,
) -> Result<u64> {
    let guest_ram_base = topology
        .memory_region_by_kind("guest_ram")
        .map(|region| region.guest_physical_base)
        .ok_or_else(|| PlatformError::conflict("machine topology is missing guest RAM"))?;
    Ok(guest_ram_base.max(reset_vector).saturating_add(offset))
}

const GUEST_KERNEL_SERVICE_ENTRIES: &[GuestKernelOperationDescriptor] = &[
    GuestKernelOperationDescriptor {
        operation: NATIVE_CALL_GUEST_UNAME,
        kind: GUEST_KERNEL_SERVICE_KIND_READ_ONLY,
        route: GUEST_KERNEL_ROUTE_FIXED_UNAME,
    },
    GuestKernelOperationDescriptor {
        operation: NATIVE_CALL_GUEST_SYSTEM_STATE,
        kind: GUEST_KERNEL_SERVICE_KIND_READ_ONLY,
        route: GUEST_KERNEL_ROUTE_FIXED_SYSTEM_STATE,
    },
    GuestKernelOperationDescriptor {
        operation: NATIVE_CALL_GUEST_SYSTEMCTL_STATUS,
        kind: GUEST_KERNEL_SERVICE_KIND_READ_ONLY,
        route: GUEST_KERNEL_ROUTE_SERVICE_STATUS,
    },
    GuestKernelOperationDescriptor {
        operation: NATIVE_CALL_GUEST_CAT,
        kind: GUEST_KERNEL_SERVICE_KIND_READ_ONLY,
        route: GUEST_KERNEL_ROUTE_FILE_READ,
    },
    GuestKernelOperationDescriptor {
        operation: NATIVE_CALL_GUEST_ECHO_REDIRECT,
        kind: GUEST_KERNEL_SERVICE_KIND_MUTATION,
        route: GUEST_KERNEL_ROUTE_FILE_WRITE,
    },
    GuestKernelOperationDescriptor {
        operation: NATIVE_CALL_GUEST_TOUCH,
        kind: GUEST_KERNEL_SERVICE_KIND_MUTATION,
        route: GUEST_KERNEL_ROUTE_FILE_TOUCH,
    },
    GuestKernelOperationDescriptor {
        operation: NATIVE_CALL_GUEST_LS,
        kind: GUEST_KERNEL_SERVICE_KIND_INDEX,
        route: GUEST_KERNEL_ROUTE_DIRECTORY_INDEX,
    },
    GuestKernelOperationDescriptor {
        operation: NATIVE_CALL_GUEST_SHA256SUM,
        kind: GUEST_KERNEL_SERVICE_KIND_INDEX,
        route: GUEST_KERNEL_ROUTE_SHA256_INDEX,
    },
    GuestKernelOperationDescriptor {
        operation: NATIVE_CALL_GUEST_UNIXBENCH,
        kind: GUEST_KERNEL_SERVICE_KIND_BENCHMARK,
        route: GUEST_KERNEL_ROUTE_UNIXBENCH,
    },
    GuestKernelOperationDescriptor {
        operation: NATIVE_CALL_GUEST_UNSUPPORTED,
        kind: GUEST_KERNEL_SERVICE_KIND_ERROR,
        route: GUEST_KERNEL_ROUTE_ERROR,
    },
    GuestKernelOperationDescriptor {
        operation: NATIVE_CALL_GUEST_HTTP_FETCH,
        kind: GUEST_KERNEL_SERVICE_KIND_NETWORK,
        route: GUEST_KERNEL_ROUTE_HTTP_FETCH,
    },
    GuestKernelOperationDescriptor {
        operation: NATIVE_CALL_GUEST_TCP_CONNECT,
        kind: GUEST_KERNEL_SERVICE_KIND_NETWORK,
        route: GUEST_KERNEL_ROUTE_TCP_CONNECT,
    },
    GuestKernelOperationDescriptor {
        operation: NATIVE_CALL_GUEST_DNS_LOOKUP,
        kind: GUEST_KERNEL_SERVICE_KIND_NETWORK,
        route: GUEST_KERNEL_ROUTE_DNS_LOOKUP,
    },
    GuestKernelOperationDescriptor {
        operation: NATIVE_CALL_GUEST_UDP_EXCHANGE,
        kind: GUEST_KERNEL_SERVICE_KIND_NETWORK,
        route: GUEST_KERNEL_ROUTE_UDP_EXCHANGE,
    },
];

/// Runtime phase of the software-backed VM skeleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftVmPhase {
    /// Spec exists but launch preparation has not started.
    Created,
    /// Guest memory and machine layout have been prepared.
    Prepared,
    /// The skeleton runner is serving the guest contract.
    Running,
    /// The skeleton runner has been stopped.
    Stopped,
}

impl SoftVmPhase {
    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Prepared => "prepared",
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

/// Minimal runtime spec for the software-backed VM skeleton.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmRuntimeSpec {
    /// Execution-class key.
    pub execution_class: String,
    /// Machine contract.
    pub machine: MachineSpec,
    /// Whether software secure boot must be enforced for this runtime.
    #[serde(default)]
    pub require_secure_boot: bool,
    /// Optional host-local firmware artifact overriding the profile lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware_artifact: Option<String>,
}

impl SoftVmRuntimeSpec {
    /// Construct a runtime spec from existing UVM phase-0 metadata.
    pub fn new(execution_class: ExecutionClass, machine: MachineSpec) -> Self {
        Self {
            execution_class: String::from(execution_class.as_str()),
            machine,
            require_secure_boot: false,
            firmware_artifact: None,
        }
    }

    /// Return a copy of the runtime spec with secure boot explicitly enforced.
    #[must_use]
    pub fn with_secure_boot(mut self, require_secure_boot: bool) -> Self {
        self.require_secure_boot = require_secure_boot;
        self
    }

    /// Return a copy of the runtime spec with an explicit firmware artifact.
    #[must_use]
    pub fn with_firmware_artifact(mut self, firmware_artifact: Option<String>) -> Self {
        self.firmware_artifact = firmware_artifact.and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        });
        self
    }

    fn reported_firmware_profile(&self) -> &str {
        self.machine.boot.firmware_profile.as_str()
    }

    fn firmware_artifact_source(&self) -> &str {
        self.firmware_artifact
            .as_deref()
            .unwrap_or_else(|| self.reported_firmware_profile())
    }

    fn validate_secure_boot_contract(&self) -> Result<()> {
        if self.require_secure_boot && direct_kernel_boot(self) {
            return Err(PlatformError::conflict(
                "software secure boot requires firmware-mediated boot semantics",
            ));
        }
        if self.require_secure_boot && self.reported_firmware_profile() != "uefi_secure" {
            return Err(PlatformError::conflict(
                "software secure boot requires firmware_profile `uefi_secure`",
            ));
        }
        Ok(())
    }
}

/// Boot-artifact loading policy for the software-backed VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftVmArtifactPolicy {
    /// Allow local files or catalog-style source previews for modeling flows.
    CatalogPreviewAllowed,
    /// Require every boot artifact to resolve to a host-local file.
    LocalFilesOnly,
}

impl SoftVmArtifactPolicy {
    const fn requires_local_files(self) -> bool {
        matches!(self, Self::LocalFilesOnly)
    }
}

/// Memory region claimed by the native software executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmMemoryRegion {
    /// Stable region name.
    pub name: String,
    /// Guest physical base address.
    pub guest_physical_base: u64,
    /// Region byte length.
    pub byte_len: u64,
    /// Whether the region is writable.
    pub writable: bool,
}

/// MMIO region exposed by the native executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmMmioRegion {
    /// Stable region name.
    pub name: String,
    /// Guest physical base address.
    pub guest_physical_base: u64,
    /// Region byte length.
    pub byte_len: u64,
    /// Read-dispatch kind for this MMIO region.
    pub read_dispatch: String,
    /// Write-dispatch kind for this MMIO region.
    pub write_dispatch: String,
}

/// MMIO access recorded by the native executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmMmioAccess {
    /// Stable MMIO region name.
    pub region_name: String,
    /// Access kind (`read` or `write`).
    pub access_kind: String,
    /// Guest physical address targeted by the MMIO access.
    pub guest_physical_address: u64,
    /// Value observed or written for the MMIO access.
    pub value: u64,
    /// Human-readable description of the MMIO access.
    pub detail: String,
}

/// Pending interrupt/event source tracked by the executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmPendingInterrupt {
    /// Interrupt vector number.
    pub vector: u8,
    /// Stable interrupt source name.
    pub source: String,
    /// Human-readable reason/detail.
    pub detail: String,
}

/// Thin writable overlay layered over a block-backed boot medium.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmWritableOverlay {
    /// Stable overlay identifier.
    pub id: String,
    /// Fingerprint of the immutable parent backing.
    pub parent_content_fingerprint: String,
    /// Logical block size used by the overlay.
    pub block_size_bytes: u32,
    /// Block-indexed overlay writes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub modified_blocks: BTreeMap<u64, Vec<u8>>,
    /// Bytes currently allocated by the thin overlay.
    pub allocated_bytes: u64,
    /// Stable fingerprint of the current overlay contents.
    pub content_fingerprint: String,
}

impl SoftVmWritableOverlay {
    fn new(id: impl Into<String>, parent_content_fingerprint: impl Into<String>) -> Self {
        let parent_content_fingerprint = parent_content_fingerprint.into();
        let mut overlay = Self {
            id: id.into(),
            parent_content_fingerprint: parent_content_fingerprint.clone(),
            block_size_bytes: DEFAULT_BLOCK_SIZE_BYTES,
            modified_blocks: BTreeMap::new(),
            allocated_bytes: 0,
            content_fingerprint: parent_content_fingerprint,
        };
        overlay.refresh_fingerprint();
        overlay
    }

    fn refresh_fingerprint(&mut self) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.id.as_bytes());
        bytes.extend_from_slice(self.parent_content_fingerprint.as_bytes());
        bytes.extend_from_slice(self.block_size_bytes.to_string().as_bytes());
        for (block_index, block) in &self.modified_blocks {
            bytes.extend_from_slice(block_index.to_string().as_bytes());
            bytes.extend_from_slice(block);
        }
        self.allocated_bytes = u64::from(self.block_size_bytes)
            .saturating_mul(u64::try_from(self.modified_blocks.len()).unwrap_or(u64::MAX));
        self.content_fingerprint = sha256_hex(&bytes);
    }
}

fn default_boot_artifact_delivery_model() -> String {
    String::from("memory_mapped_preview")
}

/// Queue state maintained by a synthetic device loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmDeviceQueue {
    /// Stable queue name.
    pub name: String,
    /// Values waiting to be drained by the loop.
    pub pending: Vec<u64>,
    /// Values already drained by the loop.
    pub completed: Vec<u64>,
}

impl SoftVmDeviceQueue {
    fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            pending: Vec::new(),
            completed: Vec::new(),
        }
    }
}

/// Synthetic device loop wired to an MMIO region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmDeviceLoop {
    /// Stable device-loop name.
    pub name: String,
    /// MMIO region owned by the device loop.
    pub region_name: String,
    /// Stable device-kind label.
    pub device_kind: String,
    /// Interrupt vector injected when the device completes work.
    pub interrupt_vector: u8,
    /// Queue state tracked by the device loop.
    pub queues: Vec<SoftVmDeviceQueue>,
    /// Compact device registers/state values keyed by stable names.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub registers: BTreeMap<String, u64>,
}

impl SoftVmDeviceLoop {
    fn new(
        name: impl Into<String>,
        region_name: impl Into<String>,
        device_kind: impl Into<String>,
        interrupt_vector: u8,
        queue_names: &[&str],
    ) -> Self {
        Self {
            name: name.into(),
            region_name: region_name.into(),
            device_kind: device_kind.into(),
            interrupt_vector,
            queues: queue_names
                .iter()
                .map(|queue_name| SoftVmDeviceQueue::new(*queue_name))
                .collect(),
            registers: BTreeMap::new(),
        }
    }

    fn queue_mut(&mut self, name: &str) -> Option<&mut SoftVmDeviceQueue> {
        self.queues.iter_mut().find(|queue| queue.name == name)
    }

    fn queue(&self, name: &str) -> Option<&SoftVmDeviceQueue> {
        self.queues.iter().find(|queue| queue.name == name)
    }

    fn queue_pending_len(&self, name: &str) -> u64 {
        self.queue(name)
            .map(|queue| saturating_u64_len(queue.pending.len()))
            .unwrap_or(0)
    }

    fn queue_completed_len(&self, name: &str) -> u64 {
        self.queue(name)
            .map(|queue| saturating_u64_len(queue.completed.len()))
            .unwrap_or(0)
    }

    fn register(&self, name: &str) -> u64 {
        self.registers.get(name).copied().unwrap_or(0)
    }

    fn set_register(&mut self, name: &str, value: u64) {
        self.registers.insert(String::from(name), value);
    }
}

/// Boot artifact loaded into the native software executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmBootArtifact {
    /// Artifact role (`firmware`, `primary_disk`, `install_media`).
    pub role: String,
    /// Original source reference.
    pub source: String,
    /// Resolved byte length.
    pub byte_len: u64,
    /// Number of bytes preview-loaded into native memory.
    ///
    /// Block-backed media expose `0` here and use `delivery_model=block_device`
    /// plus `overlay` metadata instead of a preview window.
    pub preview_loaded_bytes: usize,
    /// Guest-visible region or interface serving the artifact.
    pub mapped_region: String,
    /// Stable fingerprint of the immutable backing content or source token.
    pub content_fingerprint: String,
    /// Delivery model (`memory_mapped_preview` or `block_device`).
    #[serde(default = "default_boot_artifact_delivery_model")]
    pub delivery_model: String,
    /// Optional resolved local path for execution-backed artifacts.
    #[serde(default)]
    pub resolved_local_path: Option<String>,
    /// Logical block size for block-backed media.
    #[serde(default)]
    pub block_size_bytes: Option<u32>,
    /// Logical block count for block-backed media.
    #[serde(default)]
    pub block_count: Option<u64>,
    /// Whether the medium is read-only.
    #[serde(default)]
    pub read_only: bool,
    /// Optional thin writable overlay layered on top of the immutable backing.
    #[serde(default)]
    pub overlay: Option<SoftVmWritableOverlay>,
}

impl SoftVmBootArtifact {
    fn is_block_device(&self) -> bool {
        self.delivery_model == "block_device"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SoftVmLoadedArtifactPreview {
    local_path: Option<PathBuf>,
    byte_len: u64,
    preview: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SoftVmBlockControlTransfer {
    role: &'static str,
    role_code: u64,
    first_block_token: u64,
    byte_len: u64,
    block_count: u64,
    overlay_attached: bool,
    read_only: bool,
}

/// Simplified CPU state tracked by the native software executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmCpuState {
    /// Current instruction pointer.
    pub instruction_pointer: u64,
    /// Minimal general-purpose register file for the interpreted guest ISA.
    pub general_purpose_registers: [u64; 4],
    /// Guest stack pointer tracked by the native executor.
    pub stack_pointer: u64,
    /// Whether maskable interrupts are currently enabled.
    pub interrupts_enabled: bool,
    /// Synthetic zero-flag state.
    pub zero_flag: bool,
    /// Synthetic sign-flag state.
    pub sign_flag: bool,
    /// Synthetic carry-flag state.
    pub carry_flag: bool,
    /// Last injected trap or interrupt vector, if any.
    pub last_trap_vector: Option<u8>,
    /// Human-readable description of the last injected trap or interrupt.
    pub last_trap_detail: Option<String>,
    /// Synthetic trap-frame depth observed by the executor.
    pub trap_frame_depth: u32,
    /// Whether the executor observed a faulted guest CPU state.
    pub faulted: bool,
    /// Last guest fault vector, if any.
    pub fault_vector: Option<u8>,
    /// Human-readable description of the last guest fault.
    pub fault_detail: Option<String>,
    /// Synthetic call depth observed by the executor.
    pub call_depth: u32,
    /// Whether the executor reached a halted state.
    pub halted: bool,
}

/// Event stepped by the native software executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmExecutionEvent {
    /// Stable event kind.
    pub kind: String,
    /// Human-readable event detail.
    pub detail: String,
}

impl SoftVmExecutionEvent {
    fn new(kind: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            detail: detail.into(),
        }
    }
}

/// Resident native bytecode program staged inside the software executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmResidentProgram {
    /// Stable program name.
    pub name: String,
    /// Memory region containing the program bytes.
    pub mapped_region: String,
    /// Guest entry point used when the program is interpreted.
    pub entry_point: u64,
    /// Raw interpreted bytecode staged for execution.
    pub bytecode: Vec<u8>,
    /// Stable fingerprint over the interpreted bytecode.
    pub content_fingerprint: String,
}

impl SoftVmResidentProgram {
    fn new(
        name: impl Into<String>,
        mapped_region: impl Into<String>,
        entry_point: u64,
        bytecode: Vec<u8>,
    ) -> Self {
        Self {
            name: name.into(),
            mapped_region: mapped_region.into(),
            entry_point,
            content_fingerprint: sha256_hex(&bytecode),
            bytecode,
        }
    }
}

/// Sparse guest-RAM allocation tracked by the native executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmGuestRamAllocation {
    /// Stable allocation label.
    pub label: String,
    /// Backing region name.
    pub mapped_region: String,
    /// Guest physical start address.
    pub guest_address: u64,
    /// Number of bytes staged for the allocation.
    pub byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SoftVmDirectKernelBootState {
    kernel_source: String,
    kernel_entry_guest_address: u64,
    kernel_byte_len: u64,
    preview_byte_len: u64,
    command_line_guest_address: u64,
    command_line_byte_len: u64,
    boot_params_guest_address: u64,
    boot_params_byte_len: u64,
    command_line: String,
}

/// Guest-page permissions tracked by the native executor.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmGuestMemoryPermissions {
    /// Whether the guest can read bytes from the page.
    pub readable: bool,
    /// Whether the guest can write bytes to the page.
    pub writable: bool,
    /// Whether the guest can fetch instructions from the page.
    pub executable: bool,
}

impl SoftVmGuestMemoryPermissions {
    fn from_region(region: &SoftVmMemoryRegion) -> Self {
        Self {
            readable: true,
            writable: region.writable,
            executable: false,
        }
    }

    fn with_execute(mut self) -> Self {
        self.executable = true;
        self
    }

    fn merge(self, other: Self) -> Self {
        Self {
            readable: self.readable || other.readable,
            writable: self.writable || other.writable,
            executable: self.executable || other.executable,
        }
    }
}

/// Resident guest-memory page tracked by the software executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmGuestMemoryPage {
    /// Guest physical base address aligned to the SoftVM page size.
    pub guest_physical_base: u64,
    /// Effective permissions currently associated with the page.
    pub permissions: SoftVmGuestMemoryPermissions,
    /// Monotonic generation incremented whenever page contents or permissions change.
    pub generation: u64,
    /// Whether the page has observed a guest-originated write since it was created.
    pub dirty: bool,
    /// Resident byte offsets currently populated inside the page.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resident_bytes: BTreeMap<u16, u8>,
}

impl SoftVmGuestMemoryPage {
    fn new(guest_physical_base: u64, permissions: SoftVmGuestMemoryPermissions) -> Self {
        Self {
            guest_physical_base,
            permissions,
            generation: 0,
            dirty: false,
            resident_bytes: BTreeMap::new(),
        }
    }
}

/// Paged guest-memory view for the software executor.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmGuestMemory {
    /// Resident pages keyed by page-aligned guest physical base.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pages: BTreeMap<u64, SoftVmGuestMemoryPage>,
    /// Total number of resident bytes currently staged across all pages.
    pub resident_byte_count: u64,
}

impl SoftVmGuestMemory {
    /// Return whether the guest memory currently has no resident pages or bytes.
    pub fn is_empty(&self) -> bool {
        self.pages.is_empty() && self.resident_byte_count == 0
    }

    /// Return the number of resident bytes currently staged in guest memory.
    pub fn len(&self) -> usize {
        match usize::try_from(self.resident_byte_count) {
            Ok(len) => len,
            Err(_) => usize::MAX,
        }
    }

    /// Return the total resident byte count across all guest-memory pages.
    pub const fn resident_byte_count(&self) -> u64 {
        self.resident_byte_count
    }

    /// Lookup a resident byte by guest physical address.
    pub fn get(&self, guest_address: &u64) -> Option<&u8> {
        let page_base = Self::page_base_for_address(*guest_address);
        let page_offset = Self::page_offset_for_address(*guest_address);
        self.pages
            .get(&page_base)
            .and_then(|page| page.resident_bytes.get(&page_offset))
    }

    /// Return whether a resident byte exists at the guest physical address.
    pub fn contains_key(&self, guest_address: &u64) -> bool {
        self.get(guest_address).is_some()
    }

    /// Return the resident page covering the guest physical address, if present.
    pub fn page(&self, guest_address: u64) -> Option<&SoftVmGuestMemoryPage> {
        self.pages.get(&Self::page_base_for_address(guest_address))
    }

    fn page_base_for_address(guest_address: u64) -> u64 {
        (guest_address / SOFT_VM_GUEST_PAGE_BYTES) * SOFT_VM_GUEST_PAGE_BYTES
    }

    fn page_offset_for_address(guest_address: u64) -> u16 {
        guest_address.saturating_sub(Self::page_base_for_address(guest_address)) as u16
    }

    fn write_byte(
        &mut self,
        guest_address: u64,
        value: u8,
        permissions: SoftVmGuestMemoryPermissions,
        write_origin: SoftVmGuestMemoryWriteOrigin,
    ) -> Result<()> {
        let page_base = Self::page_base_for_address(guest_address);
        let page_offset = Self::page_offset_for_address(guest_address);
        let page = self
            .pages
            .entry(page_base)
            .or_insert_with(|| SoftVmGuestMemoryPage::new(page_base, permissions));
        let merged_permissions = page.permissions.merge(permissions);
        if write_origin.enforces_guest_writable() && !merged_permissions.writable {
            return Err(PlatformError::conflict(format!(
                "guest write to 0x{guest_address:x} violates page permissions"
            )));
        }
        let permissions_changed = merged_permissions != page.permissions;
        if permissions_changed {
            page.permissions = merged_permissions;
        }
        let previous = page.resident_bytes.insert(page_offset, value);
        if previous.is_none() {
            self.resident_byte_count = self.resident_byte_count.saturating_add(1);
        }
        if permissions_changed || previous != Some(value) {
            page.generation = page.generation.saturating_add(1);
        }
        if write_origin.tracks_dirty() {
            page.dirty = true;
        }
        Ok(())
    }

    fn remove_byte(
        &mut self,
        guest_address: u64,
        write_origin: SoftVmGuestMemoryWriteOrigin,
    ) -> Result<Option<u8>> {
        let page_base = Self::page_base_for_address(guest_address);
        let page_offset = Self::page_offset_for_address(guest_address);
        let Some(page) = self.pages.get_mut(&page_base) else {
            return Ok(None);
        };
        if write_origin.enforces_guest_writable() && !page.permissions.writable {
            return Err(PlatformError::conflict(format!(
                "guest write to 0x{guest_address:x} violates page permissions"
            )));
        }
        let previous = page.resident_bytes.remove(&page_offset);
        if previous.is_some() {
            self.resident_byte_count = self.resident_byte_count.saturating_sub(1);
            page.generation = page.generation.saturating_add(1);
            if write_origin.tracks_dirty() {
                page.dirty = true;
            }
        }
        Ok(previous)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoftVmGuestMemoryWriteOrigin {
    HostStage,
    GuestStore,
}

impl SoftVmGuestMemoryWriteOrigin {
    const fn enforces_guest_writable(self) -> bool {
        matches!(self, Self::GuestStore)
    }

    const fn tracks_dirty(self) -> bool {
        matches!(self, Self::GuestStore)
    }
}

/// Instruction trace row emitted by the native bytecode interpreter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmInstructionTrace {
    /// Program that emitted the trace row.
    pub program_name: String,
    /// Guest address of the interpreted opcode.
    pub guest_address: u64,
    /// Stable opcode name.
    pub opcode: String,
    /// Human-readable trace detail.
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SoftVmPageGenerationStamp {
    page_index: u64,
    generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SoftVmResidentProgramRange {
    resident_program_index: usize,
    guest_start_address: u64,
    guest_end_address: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoftVmDecodedInstruction {
    MovImm64 {
        guest_address: u64,
        next_guest_address: u64,
        register: u8,
        immediate: u64,
    },
    CallAbs64 {
        guest_address: u64,
        next_guest_address: u64,
        target: u64,
    },
    Ret {
        guest_address: u64,
        next_guest_address: u64,
    },
    MmioWrite64 {
        guest_address: u64,
        next_guest_address: u64,
        guest_physical_address: u64,
        value: u64,
    },
    MmioRead64 {
        guest_address: u64,
        next_guest_address: u64,
        register: u8,
        guest_physical_address: u64,
    },
    NativeCall {
        guest_address: u64,
        next_guest_address: u64,
        call_id: u8,
    },
    Halt {
        guest_address: u64,
        next_guest_address: u64,
    },
}

impl SoftVmDecodedInstruction {
    const fn next_guest_address(self) -> u64 {
        match self {
            Self::MovImm64 {
                next_guest_address, ..
            }
            | Self::CallAbs64 {
                next_guest_address, ..
            }
            | Self::Ret {
                next_guest_address, ..
            }
            | Self::MmioWrite64 {
                next_guest_address, ..
            }
            | Self::MmioRead64 {
                next_guest_address, ..
            }
            | Self::NativeCall {
                next_guest_address, ..
            }
            | Self::Halt {
                next_guest_address, ..
            } => next_guest_address,
        }
    }

    const fn terminates_block(self) -> bool {
        matches!(
            self,
            Self::CallAbs64 { .. } | Self::Ret { .. } | Self::NativeCall { .. } | Self::Halt { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SoftVmDecodedBlock {
    program_name: String,
    start_guest_address: u64,
    page_generations: Vec<SoftVmPageGenerationStamp>,
    instructions: Vec<SoftVmDecodedInstruction>,
}

impl SoftVmDecodedBlock {
    fn is_current(&self, execution: &SoftVmExecutionCore) -> bool {
        self.page_generations.iter().all(|stamp| {
            execution
                .guest_memory_bytes
                .page(guest_page_base(stamp.page_index))
                .map(|page| page.generation)
                .unwrap_or_default()
                == stamp.generation
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoftVmFaultLookupKind {
    ExecutableGap,
    MappedNonExecutable,
    Unmapped,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct SoftVmDbtStats {
    decoded_block_cache_hits: u64,
    decoded_block_cache_misses: u64,
    trace_chain_hits: u64,
    decoded_block_invalidations: u64,
    fast_fault_lookups: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SoftVmProgramExecutionKind {
    Boot,
    Guest,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct SoftVmProgramOutcome {
    stages: Vec<String>,
    console_trace: Vec<String>,
    guest_control_ready: bool,
    stdout: String,
    stderr: String,
    exit_code: i32,
    instruction_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SoftVmInjectedInterrupt {
    vector: u8,
    source: String,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SoftVmDeviceMmioEffect {
    value: u64,
    detail: String,
    interrupt: Option<SoftVmInjectedInterrupt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestFileProjection {
    path: String,
    contents: String,
}

impl GuestFileProjection {
    fn new(path: impl Into<String>, contents: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            contents: contents.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BootServiceRouteRequest {
    stage: u8,
}

impl BootServiceRouteRequest {
    fn decode(execution: &SoftVmExecutionCore) -> Result<Self> {
        let stage = u8::try_from(execution.read_register(ISA_REGISTER_ARG1)?)
            .map_err(|_| PlatformError::invalid("boot-service stage register exceeds u8"))?;
        Ok(Self { stage })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BootServiceMmioWriteDescriptor {
    device_kind: &'static str,
    value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BootServiceRuntimeMmioAccess {
    region_name: String,
    access_kind: &'static str,
    guest_physical_address: u64,
    value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootServiceStageEffect {
    FirmwareDispatch,
    DirectKernelEntry,
    InstallMediaProbe,
    BootDeviceTransfer,
    UserspaceControl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BootServiceStageCompletion {
    event_kind: &'static str,
    detail: String,
    stage_marker: String,
    console_line: String,
    guest_control_ready: bool,
    mmio_access: Option<BootServiceRuntimeMmioAccess>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BootServiceStageDescriptor {
    call_id: u8,
    effect: BootServiceStageEffect,
    pre_dispatch_mmio_write: Option<BootServiceMmioWriteDescriptor>,
}

impl BootServiceStageEffect {
    fn completion(
        self,
        spec: &SoftVmRuntimeSpec,
        execution: &SoftVmExecutionCore,
    ) -> Result<BootServiceStageCompletion> {
        Ok(match self {
            Self::FirmwareDispatch => {
                let detail = format!(
                    "firmware {} dispatches from reset vector",
                    spec.machine.boot.firmware_profile
                );
                BootServiceStageCompletion {
                    event_kind: "firmware_dispatch",
                    detail: detail.clone(),
                    stage_marker: String::from("firmware:dispatch_complete"),
                    console_line: detail,
                    guest_control_ready: false,
                    mmio_access: None,
                }
            }
            Self::DirectKernelEntry => {
                let detail = format!(
                    "direct kernel {} entered from reset vector",
                    spec.machine.boot.firmware_profile
                );
                BootServiceStageCompletion {
                    event_kind: "direct_kernel_entry",
                    detail: detail.clone(),
                    stage_marker: String::from("direct_kernel:entry_complete"),
                    console_line: detail,
                    guest_control_ready: false,
                    mmio_access: None,
                }
            }
            Self::InstallMediaProbe => {
                let detail = format!(
                    "installer media preview available from {}",
                    spec.machine
                        .boot
                        .cdrom_image
                        .as_deref()
                        .unwrap_or("unknown")
                );
                BootServiceStageCompletion {
                    event_kind: "install_media_probe",
                    detail: detail.clone(),
                    stage_marker: String::from("install_media:manifest_loaded"),
                    console_line: detail,
                    guest_control_ready: false,
                    mmio_access: Some(boot_service_runtime_mmio_access(
                        execution,
                        "block_control",
                        "read",
                        1,
                    )?),
                }
            }
            Self::BootDeviceTransfer => {
                let detail = format!(
                    "boot device {} selected for handoff",
                    spec.machine.boot.primary_boot_device
                );
                let (value, stage_marker, console_line) = if spec.machine.boot.primary_boot_device
                    == "cdrom"
                {
                    (
                        2u64,
                        String::from("installer_environment:ready"),
                        String::from(
                            "Installer environment reached control-ready state under native executor",
                        ),
                    )
                } else {
                    (
                        1u64,
                        String::from("primary_disk:handoff_complete"),
                        String::from(
                            "Primary disk handoff reached guest userspace under native executor",
                        ),
                    )
                };
                BootServiceStageCompletion {
                    event_kind: "boot_device_transfer",
                    detail,
                    stage_marker,
                    console_line,
                    guest_control_ready: false,
                    mmio_access: Some(boot_service_runtime_mmio_access(
                        execution,
                        "block_control",
                        "write",
                        value,
                    )?),
                }
            }
            Self::UserspaceControl => {
                let detail = String::from("native executor reached guest control handoff");
                BootServiceStageCompletion {
                    event_kind: "userspace_control",
                    detail: detail.clone(),
                    stage_marker: String::from("native_control:ready"),
                    console_line: detail,
                    guest_control_ready: true,
                    mmio_access: Some(boot_service_runtime_mmio_access(
                        execution, "console", "write", 1,
                    )?),
                }
            }
        })
    }
}

fn boot_service_runtime_mmio_access(
    execution: &SoftVmExecutionCore,
    device_kind: &str,
    access_kind: &'static str,
    value: u64,
) -> Result<BootServiceRuntimeMmioAccess> {
    let device = execution
        .machine_topology
        .device_by_kind(device_kind)
        .ok_or_else(|| {
            PlatformError::conflict(format!(
                "machine topology is missing `{device_kind}` device"
            ))
        })?;
    Ok(BootServiceRuntimeMmioAccess {
        region_name: device.name.clone(),
        access_kind,
        guest_physical_address: device.guest_physical_base,
        value,
    })
}

impl BootServiceStageDescriptor {
    fn dispatch(
        self,
        execution: &mut SoftVmExecutionCore,
        spec: &SoftVmRuntimeSpec,
        outcome: &mut SoftVmProgramOutcome,
    ) -> Result<()> {
        let completion = match self.effect {
            BootServiceStageEffect::DirectKernelEntry => execution.enter_direct_kernel()?,
            _ => self.effect.completion(spec, execution)?,
        };
        let BootServiceStageCompletion {
            event_kind,
            detail,
            stage_marker,
            console_line,
            guest_control_ready,
            mmio_access,
        } = completion;
        if let Some(mmio_access) = mmio_access {
            if mmio_access.access_kind == "write" {
                let _ = execution.dispatch_mmio_write(
                    mmio_access.guest_physical_address,
                    mmio_access.value,
                    Some(detail.clone()),
                )?;
            } else {
                let _ = execution.dispatch_mmio_read(mmio_access.guest_physical_address)?;
            }
        }
        execution.complete_boot_stage(
            outcome,
            event_kind,
            detail,
            stage_marker,
            console_line,
            guest_control_ready,
        );
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct BootServiceDispatchIntent {
    request: BootServiceRouteRequest,
    descriptor: BootServiceStageDescriptor,
}

impl BootServiceDispatchIntent {
    fn decode(execution: &mut SoftVmExecutionCore) -> Result<Self> {
        let request = BootServiceRouteRequest::decode(execution)?;
        let Some(descriptor) = boot_service_stage_descriptor(request.stage) else {
            return execution.raise_fault(
                0x0d,
                format!("unsupported boot-service stage `0x{:02x}`", request.stage),
            );
        };
        Ok(Self {
            request,
            descriptor,
        })
    }

    fn trace_detail(self) -> String {
        format!(
            "boot stage {} executed through boot_service",
            native_call_name(self.request.stage)
        )
    }

    fn record_trace(self, execution: &mut SoftVmExecutionCore) -> Result<()> {
        let boot_service = execution.resident_program_named("boot_service")?.clone();
        execution.record_trace(
            &boot_service,
            execution.cpu_state.instruction_pointer.saturating_sub(2),
            self.request.stage,
            self.trace_detail(),
        );
        Ok(())
    }

    fn dispatch(
        self,
        execution: &mut SoftVmExecutionCore,
        spec: &SoftVmRuntimeSpec,
        outcome: &mut SoftVmProgramOutcome,
    ) -> Result<()> {
        self.descriptor.dispatch(execution, spec, outcome)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuestKernelRouteRequest {
    declared_kind: u8,
    route: u8,
    operation: u8,
    arg0_addr: u64,
    arg0_len: u64,
    arg1_addr: u64,
    arg1_len: u64,
}

impl GuestKernelRouteRequest {
    fn decode(execution: &SoftVmExecutionCore) -> Result<Self> {
        let request_addr = execution.read_register(ISA_REGISTER_ARG0)?;
        let declared_kind = u8::try_from(execution.read_register(ISA_REGISTER_ARG1)?)
            .map_err(|_| PlatformError::invalid("guest-kernel service kind register exceeds u8"))?;
        let route = u8::try_from(execution.read_register(ISA_REGISTER_ARG2)?).map_err(|_| {
            PlatformError::invalid("guest-kernel service route register exceeds u8")
        })?;
        let operation =
            u8::try_from(execution.read_register(ISA_REGISTER_ARG3)?).map_err(|_| {
                PlatformError::invalid("guest-kernel service operation register exceeds u8")
            })?;
        let (request_operation, arg0_addr, arg0_len, arg1_addr, arg1_len) =
            read_guest_kernel_request(execution, request_addr)?;
        if request_operation != operation {
            return Err(PlatformError::conflict(
                "guest-kernel request operation does not match dispatched service",
            ));
        }
        Ok(Self {
            declared_kind,
            route,
            operation,
            arg0_addr,
            arg0_len,
            arg1_addr,
            arg1_len,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuestKernelServiceDescriptor {
    operation: GuestKernelOperationDescriptor,
    entry_point: u64,
}

impl GuestKernelServiceDescriptor {
    fn operation_name(self) -> &'static str {
        self.operation.operation_name()
    }

    fn validate_request(self, request: GuestKernelRouteRequest) -> Result<()> {
        if request.declared_kind != self.operation.kind || request.route != self.operation.route {
            return Err(PlatformError::conflict(
                "guest-kernel service registers do not match descriptor",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct GuestKernelDispatchIntent {
    request: GuestKernelRouteRequest,
    service: GuestKernelServiceDescriptor,
    vcpu: u16,
    guest_memory_bytes: u64,
}

impl GuestKernelDispatchIntent {
    fn decode(execution: &SoftVmExecutionCore, vcpu: u16, guest_memory_bytes: u64) -> Result<Self> {
        let request = GuestKernelRouteRequest::decode(execution)?;
        let service = guest_kernel_service_descriptor(execution, request.operation)?;
        service.validate_request(request)?;
        Ok(Self {
            request,
            service,
            vcpu,
            guest_memory_bytes,
        })
    }

    fn operation_name(&self) -> &'static str {
        self.service.operation_name()
    }

    fn trace_detail(&self) -> String {
        format!(
            "guest-kernel route {} executed via {}:{}",
            self.operation_name(),
            guest_kernel_service_kind_name(self.request.declared_kind),
            guest_kernel_service_route_name(self.request.route)
        )
    }

    fn record_trace(&self, execution: &mut SoftVmExecutionCore) -> Result<()> {
        let service_program = execution
            .resident_program_named("guest_kernel_service")?
            .clone();
        execution.record_trace(
            &service_program,
            execution.cpu_state.instruction_pointer.saturating_sub(2),
            self.request.operation,
            self.trace_detail(),
        );
        Ok(())
    }

    fn invocation(&self) -> GuestKernelRouteInvocation {
        GuestKernelRouteInvocation::new(
            String::from(self.operation_name()),
            self.request,
            self.vcpu,
            self.guest_memory_bytes,
        )
    }

    fn route_descriptor(
        &self,
        execution: &mut SoftVmExecutionCore,
    ) -> Result<GuestKernelRouteDescriptor> {
        match guest_kernel_route_descriptor(self.service.operation.route) {
            Some(descriptor) => Ok(descriptor),
            None => execution.raise_fault(
                0x0d,
                format!(
                    "unsupported guest-kernel service route `0x{:02x}`",
                    self.service.operation.route
                ),
            ),
        }
    }

    fn dispatch(
        &self,
        execution: &mut SoftVmExecutionCore,
        control: &mut SoftVmGuestControl,
    ) -> Result<()> {
        let descriptor = self.route_descriptor(execution)?;
        let invocation = self.invocation();
        descriptor
            .dispatch
            .dispatch(execution, control, &invocation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestKernelRouteInvocation {
    operation_name: String,
    arg0_addr: u64,
    arg0_len: u64,
    arg1_addr: u64,
    arg1_len: u64,
    vcpu: u16,
    guest_memory_bytes: u64,
}

impl GuestKernelRouteInvocation {
    fn new(
        operation_name: String,
        request: GuestKernelRouteRequest,
        vcpu: u16,
        guest_memory_bytes: u64,
    ) -> Self {
        Self {
            operation_name,
            arg0_addr: request.arg0_addr,
            arg0_len: request.arg0_len,
            arg1_addr: request.arg1_addr,
            arg1_len: request.arg1_len,
            vcpu,
            guest_memory_bytes,
        }
    }

    fn read_arg0(&self, execution: &SoftVmExecutionCore) -> Result<String> {
        execution.read_guest_string_from_span(self.arg0_addr, self.arg0_len)
    }

    fn read_arg1(&self, execution: &SoftVmExecutionCore) -> Result<String> {
        execution.read_guest_string_from_span(self.arg1_addr, self.arg1_len)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestKernelResolvedLookup {
    subject: String,
    lookup_path: String,
}

impl GuestKernelResolvedLookup {
    fn direct(path: String) -> Self {
        Self {
            subject: path.clone(),
            lookup_path: path,
        }
    }

    fn new(subject: impl Into<String>, lookup_path: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            lookup_path: lookup_path.into(),
        }
    }
}

type GuestKernelLookupResolver =
    fn(&SoftVmExecutionCore, &GuestKernelRouteInvocation) -> Result<GuestKernelResolvedLookup>;
type GuestKernelMissingFormatter = fn(&str) -> String;

#[derive(Clone, Copy)]
struct GuestKernelLookupMissingBehavior {
    exit_code: i32,
    stderr: GuestKernelMissingFormatter,
    treat_empty_as_missing: bool,
}

#[derive(Clone, Copy)]
enum GuestKernelMutationBehavior {
    WritePayloadWithTrailingNewline,
    TouchIfMissing,
}

#[derive(Clone, Copy)]
enum GuestKernelRouteDispatch {
    RequiredFile {
        path: &'static str,
        unavailable_message: &'static str,
    },
    LookupFile {
        resolve: GuestKernelLookupResolver,
        missing: GuestKernelLookupMissingBehavior,
    },
    Mutation(GuestKernelMutationBehavior),
    BenchmarkSummary,
    ErrorResult,
    HttpFetch,
    TcpConnect,
    DnsLookup,
    UdpExchange,
}

#[derive(Clone, Copy)]
struct GuestKernelRouteDescriptor {
    route: u8,
    dispatch: GuestKernelRouteDispatch,
}

impl GuestKernelRouteDispatch {
    fn dispatch(
        self,
        execution: &mut SoftVmExecutionCore,
        control: &mut SoftVmGuestControl,
        invocation: &GuestKernelRouteInvocation,
    ) -> Result<()> {
        match self {
            Self::RequiredFile {
                path,
                unavailable_message,
            } => {
                let stdout = read_guest_file(execution, control, path)
                    .ok_or_else(|| PlatformError::unavailable(unavailable_message))?;
                execution.write_guest_kernel_result(
                    control,
                    invocation.operation_name.as_str(),
                    0,
                    &stdout,
                    "",
                )
            }
            Self::LookupFile { resolve, missing } => {
                let lookup = resolve(execution, invocation)?;
                execution.write_guest_kernel_file_lookup_result(
                    control,
                    invocation.operation_name.as_str(),
                    &lookup,
                    missing,
                )
            }
            Self::Mutation(behavior) => {
                execution.execute_guest_kernel_mutation_route(control, invocation, behavior)
            }
            Self::BenchmarkSummary => execution.execute_guest_route_unixbench(control, invocation),
            Self::ErrorResult => execution.execute_guest_route_error(control, invocation),
            Self::HttpFetch => execution.execute_guest_route_http_fetch(control, invocation),
            Self::TcpConnect => execution.execute_guest_route_tcp_connect(control, invocation),
            Self::DnsLookup => execution.execute_guest_route_dns_lookup(control, invocation),
            Self::UdpExchange => execution.execute_guest_route_udp_exchange(control, invocation),
        }
    }
}

/// Minimal internal execution core for the software-backed runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmExecutionCore {
    /// Guest architecture key.
    pub guest_architecture: String,
    /// Per-family machine topology used to resolve addresses and IRQ vectors.
    pub machine_topology: MachineTopology,
    /// Guest reset vector used by the native executor.
    pub reset_vector: u64,
    /// Internal dispatch step counter.
    pub steps_executed: u64,
    /// Simplified CPU state advanced by the event loop.
    pub cpu_state: SoftVmCpuState,
    /// Memory regions reserved by the executor.
    pub memory_regions: Vec<SoftVmMemoryRegion>,
    /// MMIO regions exposed by the executor.
    pub mmio_regions: Vec<SoftVmMmioRegion>,
    /// Recorded MMIO accesses performed by the executor.
    pub mmio_access_log: Vec<SoftVmMmioAccess>,
    /// Boot artifacts staged or attached to the executor.
    pub boot_artifacts: Vec<SoftVmBootArtifact>,
    /// Resident programs staged into guest-visible memory.
    pub resident_programs: Vec<SoftVmResidentProgram>,
    /// Paged guest memory staged by the executor, including page permissions and dirty state.
    #[serde(default, skip_serializing_if = "SoftVmGuestMemory::is_empty")]
    pub guest_memory_bytes: SoftVmGuestMemory,
    /// Named allocations currently backed inside guest memory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guest_ram_allocations: Vec<SoftVmGuestRamAllocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    direct_kernel_state: Option<SoftVmDirectKernelBootState>,
    /// Events waiting to be processed.
    pub pending_events: Vec<SoftVmExecutionEvent>,
    /// Events already processed by the executor.
    pub completed_events: Vec<SoftVmExecutionEvent>,
    /// Interpreted instruction trace rows across boot and guest-control programs.
    pub instruction_trace: Vec<SoftVmInstructionTrace>,
    /// Stateful device loops exposed through the MMIO map.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_loops: Vec<SoftVmDeviceLoop>,
    /// Pending interrupt sources waiting to be serviced.
    pub pending_interrupts: Vec<SoftVmPendingInterrupt>,
    /// Next guest entry point reserved for transient command programs.
    pub next_program_entry: u64,
    /// Next guest-RAM address reserved for resident data blobs.
    pub next_guest_data_address: u64,
    #[serde(skip)]
    executable_page_lookup: BTreeMap<u64, Vec<SoftVmResidentProgramRange>>,
    #[serde(skip)]
    decoded_block_cache: BTreeMap<u64, SoftVmDecodedBlock>,
    #[serde(skip)]
    decoded_block_pages: BTreeMap<u64, BTreeSet<u64>>,
    #[serde(skip)]
    dbt_stats: SoftVmDbtStats,
}

impl SoftVmExecutionCore {
    /// Create the native execution-core view from a runtime spec.
    pub fn from_spec(spec: &SoftVmRuntimeSpec, memory: &MemoryLayout) -> Result<Self> {
        Self::from_spec_with_artifact_policy(
            spec,
            memory,
            SoftVmArtifactPolicy::CatalogPreviewAllowed,
        )
    }

    /// Create the native execution-core view from a runtime spec under an explicit artifact policy.
    pub fn from_spec_with_artifact_policy(
        spec: &SoftVmRuntimeSpec,
        memory: &MemoryLayout,
        artifact_policy: SoftVmArtifactPolicy,
    ) -> Result<Self> {
        spec.validate_secure_boot_contract()?;
        let topology = memory.topology.clone();
        let boot_region = topology
            .memory_region_named(boot_code_region_name(spec))
            .map(softvm_memory_region_from_machine_region)
            .ok_or_else(|| {
                PlatformError::conflict(format!(
                    "machine topology is missing boot region `{}`",
                    boot_code_region_name(spec)
                ))
            })?;
        let ram_region = topology
            .memory_region_by_kind("guest_ram")
            .map(softvm_memory_region_from_machine_region)
            .ok_or_else(|| PlatformError::conflict("machine topology is missing guest RAM"))?;
        let mmio_regions = topology
            .devices
            .iter()
            .map(softvm_mmio_region_from_machine_device)
            .collect::<Vec<_>>();
        let device_loops = softvm_device_loops(&topology)?;
        let guest_stack_pointer = ram_region
            .guest_physical_base
            .saturating_add(ram_region.byte_len)
            .saturating_sub(0x1000);
        let memory_regions = vec![ram_region.clone(), boot_region.clone()];
        let mut boot_artifacts = vec![
            load_boot_artifact_with_policy(
                boot_artifact_role(spec),
                spec.firmware_artifact_source(),
                &boot_region.name,
                artifact_policy,
            )?,
            load_block_boot_artifact_with_policy(
                "primary_disk",
                &spec.machine.boot.disk_image,
                artifact_policy,
                false,
            )?,
        ];
        if let Some(cdrom_image) = spec.machine.boot.cdrom_image.as_ref() {
            boot_artifacts.push(load_block_boot_artifact_with_policy(
                "install_media",
                cdrom_image,
                artifact_policy,
                true,
            )?);
        }

        let reset_vector = topology.reset_vector;
        let boot_service_program =
            build_boot_service_program(spec, &topology, reset_vector.saturating_add(0x400))?;
        let resident_programs = vec![
            build_boot_program(spec, reset_vector, &boot_service_program)?,
            boot_service_program,
            build_guest_kernel_service_program(guest_program_entry_base(
                &topology,
                reset_vector,
                0x800,
            )?),
        ];
        let mut core = Self {
            guest_architecture: spec.machine.guest_architecture.clone(),
            machine_topology: topology.clone(),
            reset_vector,
            steps_executed: 0,
            cpu_state: SoftVmCpuState {
                instruction_pointer: reset_vector,
                general_purpose_registers: [0; 4],
                stack_pointer: guest_stack_pointer,
                interrupts_enabled: true,
                zero_flag: false,
                sign_flag: false,
                carry_flag: false,
                last_trap_vector: None,
                last_trap_detail: None,
                trap_frame_depth: 0,
                faulted: false,
                fault_vector: None,
                fault_detail: None,
                call_depth: 0,
                halted: false,
            },
            memory_regions,
            mmio_regions,
            mmio_access_log: Vec::new(),
            boot_artifacts,
            resident_programs,
            guest_memory_bytes: SoftVmGuestMemory::default(),
            guest_ram_allocations: Vec::new(),
            direct_kernel_state: None,
            pending_events: Vec::new(),
            completed_events: Vec::new(),
            instruction_trace: Vec::new(),
            device_loops,
            pending_interrupts: Vec::new(),
            next_program_entry: guest_program_entry_base(&topology, reset_vector, 0x1000)?,
            next_guest_data_address: ram_region
                .guest_physical_base
                .saturating_add(GUEST_RAM_DATA_BASE),
            executable_page_lookup: BTreeMap::new(),
            decoded_block_cache: BTreeMap::new(),
            decoded_block_pages: BTreeMap::new(),
            dbt_stats: SoftVmDbtStats::default(),
        };
        for program in core.resident_programs.clone() {
            core.stage_resident_program(&program)?;
        }
        core.prepare_direct_kernel_boot(spec, artifact_policy)?;
        core.rebuild_executable_page_lookup();
        Ok(core)
    }

    /// Run the minimal native boot sequence and emit a boot witness.
    pub fn run_boot_sequence(&mut self, spec: &SoftVmRuntimeSpec) -> SoftVmBootWitness {
        let boot_artifact_profile = spec.reported_firmware_profile().to_owned();
        let boot_device = spec.machine.boot.primary_boot_device.clone();
        let install_media_attached = spec.machine.boot.cdrom_image.is_some();
        let stage_prefix = boot_stage_prefix(spec);
        let boot_banner = if direct_kernel_boot(spec) {
            "Direct kernel"
        } else {
            "Firmware"
        };

        let mut stages = vec![
            format!("native_executor:{}:ready", self.guest_architecture),
            format!("reset_vector:0x{:x}", self.reset_vector),
            format!("{stage_prefix}:{}:mapped", boot_artifact_profile),
            format!("boot_device:{boot_device}:selected"),
        ];
        let block_artifact_count = self
            .boot_artifacts
            .iter()
            .filter(|artifact| artifact.is_block_device())
            .count();
        let preview_artifact_count = self
            .boot_artifacts
            .len()
            .saturating_sub(block_artifact_count);
        let mut console_trace = vec![format!(
            "Native executor mapped {preview_artifact_count} preview artifacts and attached {block_artifact_count} block devices across {} memory regions",
            self.memory_regions.len()
        )];
        console_trace.push(format!(
            "{boot_banner} {} dispatching from reset vector 0x{:x}",
            boot_artifact_profile, self.reset_vector
        ));
        let secure_boot_measurements =
            self.record_secure_boot_semantics(spec, &mut stages, &mut console_trace);
        let outcome = match self.execute_boot_program(spec) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.cpu_state.halted = true;
                stages.push(String::from("native_executor:error"));
                console_trace.push(format!("native executor failed: {}", error.message));
                return SoftVmBootWitness {
                    firmware_profile: boot_artifact_profile,
                    boot_device,
                    install_media_attached,
                    stages,
                    console_trace,
                    secure_boot_enabled: spec.require_secure_boot,
                    secure_boot_measurements,
                    guest_control_ready: false,
                };
            }
        };
        stages.extend(outcome.stages);
        console_trace.extend(outcome.console_trace);
        SoftVmBootWitness {
            firmware_profile: boot_artifact_profile,
            boot_device,
            install_media_attached,
            stages,
            console_trace,
            secure_boot_enabled: spec.require_secure_boot,
            secure_boot_measurements,
            guest_control_ready: outcome.guest_control_ready,
        }
    }

    /// Read bytes from a block-backed boot medium.
    pub fn read_boot_artifact_range(
        &self,
        role: &str,
        offset: u64,
        byte_len: usize,
    ) -> Result<Vec<u8>> {
        if byte_len == 0 {
            return Ok(Vec::new());
        }
        let artifact = self.find_boot_artifact(role)?;
        read_block_artifact_range(role, artifact, offset, byte_len)
    }

    /// Write bytes into the thin overlay for a writable block-backed boot medium.
    pub fn write_boot_artifact_overlay(
        &mut self,
        role: &str,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let artifact = self.find_boot_artifact_mut(role)?;
        if !artifact.is_block_device() {
            return Err(PlatformError::conflict(format!(
                "{role} is not exposed through the block substrate"
            )));
        }
        if artifact.read_only {
            return Err(PlatformError::conflict(format!(
                "{role} is read-only and cannot accept overlay writes"
            )));
        }
        let block_size_bytes = artifact.block_size_bytes.ok_or_else(|| {
            PlatformError::conflict(format!(
                "{role} is missing block geometry for overlay writes"
            ))
        })?;
        validate_block_artifact_range(role, artifact, offset, bytes.len())?;
        let source = artifact.source.clone();
        let resolved_local_path = artifact.resolved_local_path.clone();
        let byte_len = artifact.byte_len;
        let parent_content_fingerprint = artifact.content_fingerprint.clone();
        let mut overlay = artifact.overlay.take().unwrap_or_else(|| {
            SoftVmWritableOverlay::new(format!("{role}_overlay"), parent_content_fingerprint)
        });
        let block_size_u64 = u64::from(block_size_bytes);
        let byte_end = offset.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let first_block = offset / block_size_u64;
        let last_block = byte_end.saturating_sub(1) / block_size_u64;

        for block_index in first_block..=last_block {
            let block_start = block_index.saturating_mul(block_size_u64);
            let mut block = if let Some(existing) = overlay.modified_blocks.get(&block_index) {
                existing.clone()
            } else {
                read_block_artifact_backing_block(
                    role,
                    &source,
                    resolved_local_path.as_deref(),
                    byte_len,
                    block_size_bytes,
                    block_index,
                )?
            };
            let write_start = offset.max(block_start);
            let write_end = byte_end.min(block_start.saturating_add(block_size_u64));
            let source_start =
                usize::try_from(write_start.saturating_sub(offset)).map_err(|_| {
                    PlatformError::invalid("overlay write offset exceeds addressability")
                })?;
            let target_start =
                usize::try_from(write_start.saturating_sub(block_start)).map_err(|_| {
                    PlatformError::invalid("overlay block offset exceeds addressability")
                })?;
            let target_end = usize::try_from(write_end.saturating_sub(block_start))
                .map_err(|_| PlatformError::invalid("overlay block end exceeds addressability"))?;
            let source_end = source_start.saturating_add(target_end.saturating_sub(target_start));
            block[target_start..target_end].copy_from_slice(&bytes[source_start..source_end]);
            overlay.modified_blocks.insert(block_index, block);
        }

        overlay.refresh_fingerprint();
        artifact.overlay = Some(overlay);
        Ok(())
    }

    fn find_boot_artifact(&self, role: &str) -> Result<&SoftVmBootArtifact> {
        self.boot_artifacts
            .iter()
            .find(|artifact| artifact.role == role)
            .ok_or_else(|| PlatformError::not_found(format!("{role} boot artifact is not present")))
    }

    fn find_boot_artifact_mut(&mut self, role: &str) -> Result<&mut SoftVmBootArtifact> {
        self.boot_artifacts
            .iter_mut()
            .find(|artifact| artifact.role == role)
            .ok_or_else(|| PlatformError::not_found(format!("{role} boot artifact is not present")))
    }

    fn device_loop_index_by_region(&self, region_name: &str) -> Option<usize> {
        self.device_loops
            .iter()
            .position(|device_loop| device_loop.region_name == region_name)
    }

    fn device_loop_index_by_name(&self, name: &str) -> Option<usize> {
        self.device_loops
            .iter()
            .position(|device_loop| device_loop.name == name)
    }

    fn interrupt_trigger_for_source(&self, source: &str) -> Option<&str> {
        self.machine_topology
            .interrupt_for_source(source)
            .map(|interrupt| interrupt.trigger.as_str())
    }

    fn pending_interrupt_count_for_source(&self, source: &str) -> u64 {
        saturating_u64_len(
            self.pending_interrupts
                .iter()
                .filter(|interrupt| interrupt.source == source)
                .count(),
        )
    }

    fn clear_pending_interrupts_for_source(&mut self, source: &str) -> u64 {
        let original_len = self.pending_interrupts.len();
        self.pending_interrupts
            .retain(|interrupt| interrupt.source != source);
        saturating_u64_len(original_len.saturating_sub(self.pending_interrupts.len()))
    }

    fn device_interrupt_state_bits(&self, device_loop_index: usize) -> u64 {
        let device_loop = &self.device_loops[device_loop_index];
        let mut state = u64::from(device_loop.interrupt_vector) << 32;
        if self.pending_interrupt_count_for_source(device_loop.name.as_str()) != 0 {
            state |= DEVICE_INTERRUPT_STATE_PENDING;
        }
        if device_loop.register("interrupt_masked") != 0 {
            state |= DEVICE_INTERRUPT_STATE_MASKED;
        }
        if device_loop.register("interrupt_latched") != 0 {
            state |= DEVICE_INTERRUPT_STATE_LATCHED;
        }
        state
    }

    fn device_loop_has_pending_level_work(&self, device_loop_index: usize) -> bool {
        let device_loop = &self.device_loops[device_loop_index];
        match device_loop.name.as_str() {
            "virt_block_control" => device_loop
                .queue("responses")
                .is_some_and(|queue| !queue.pending.is_empty()),
            "uart_console" => device_loop
                .queue("rx")
                .is_some_and(|queue| !queue.pending.is_empty()),
            "virtio_console" => device_loop
                .queue("rx")
                .is_some_and(|queue| !queue.pending.is_empty()),
            "virtio_rng" => device_loop
                .queue("entropy")
                .is_some_and(|queue| !queue.pending.is_empty()),
            "virtio_net" => device_loop
                .queue("rx")
                .is_some_and(|queue| !queue.pending.is_empty()),
            _ => false,
        }
    }

    fn handle_device_interrupt_control_write(
        &mut self,
        device_loop_index: usize,
        guest_physical_address: u64,
        value: u64,
    ) -> SoftVmDeviceMmioEffect {
        let source = self.device_loops[device_loop_index].name.clone();
        let vector = self.device_loops[device_loop_index].interrupt_vector;
        match value {
            DEVICE_INTERRUPT_CONTROL_ACK => {
                let cleared = self.clear_pending_interrupts_for_source(source.as_str());
                let pending_count = self.pending_interrupt_count_for_source(source.as_str());
                {
                    let device_loop = &mut self.device_loops[device_loop_index];
                    device_loop.set_register(
                        "interrupt_ack_count",
                        device_loop
                            .register("interrupt_ack_count")
                            .saturating_add(1),
                    );
                    device_loop.set_register("interrupt_pending", pending_count);
                }
                let reassert = self.interrupt_trigger_for_source(source.as_str())
                    == Some("level_high")
                    && self.device_loops[device_loop_index].register("interrupt_masked") == 0
                    && self.device_loop_has_pending_level_work(device_loop_index);
                let detail = if reassert {
                    format!(
                        "{source} acknowledged {cleared} interrupt(s) and reasserted pending level work @ 0x{guest_physical_address:x}"
                    )
                } else {
                    format!(
                        "{source} acknowledged {cleared} interrupt(s) @ 0x{guest_physical_address:x}"
                    )
                };
                SoftVmDeviceMmioEffect {
                    value: cleared,
                    detail,
                    interrupt: reassert.then_some(SoftVmInjectedInterrupt {
                        vector,
                        source,
                        detail: String::from("level interrupt reasserted while work remained"),
                    }),
                }
            }
            DEVICE_INTERRUPT_CONTROL_MASK => {
                {
                    let device_loop = &mut self.device_loops[device_loop_index];
                    device_loop.set_register("interrupt_masked", 1);
                }
                SoftVmDeviceMmioEffect {
                    value: self.device_interrupt_state_bits(device_loop_index),
                    detail: format!(
                        "{source} masked interrupt delivery @ 0x{guest_physical_address:x}"
                    ),
                    interrupt: None,
                }
            }
            DEVICE_INTERRUPT_CONTROL_UNMASK => {
                {
                    let device_loop = &mut self.device_loops[device_loop_index];
                    device_loop.set_register("interrupt_masked", 0);
                }
                let replay = self.device_loops[device_loop_index].register("interrupt_latched")
                    != 0
                    || (self.interrupt_trigger_for_source(source.as_str()) == Some("level_high")
                        && self.device_loop_has_pending_level_work(device_loop_index));
                if replay {
                    self.device_loops[device_loop_index].set_register("interrupt_latched", 0);
                }
                SoftVmDeviceMmioEffect {
                    value: self.device_interrupt_state_bits(device_loop_index),
                    detail: if replay {
                        format!(
                            "{source} unmasked interrupt delivery and replayed deferred work @ 0x{guest_physical_address:x}"
                        )
                    } else {
                        format!(
                            "{source} unmasked interrupt delivery @ 0x{guest_physical_address:x}"
                        )
                    },
                    interrupt: replay.then_some(SoftVmInjectedInterrupt {
                        vector,
                        source,
                        detail: String::from("replayed deferred interrupt after unmask"),
                    }),
                }
            }
            _ => SoftVmDeviceMmioEffect {
                value,
                detail: format!(
                    "{source} ignored unsupported interrupt control value 0x{value:x} @ 0x{guest_physical_address:x}"
                ),
                interrupt: None,
            },
        }
    }

    fn handle_device_interrupt_control_read(
        &self,
        device_loop_index: usize,
        guest_physical_address: u64,
    ) -> SoftVmDeviceMmioEffect {
        let device_loop = &self.device_loops[device_loop_index];
        let value = self.device_interrupt_state_bits(device_loop_index);
        SoftVmDeviceMmioEffect {
            value,
            detail: format!(
                "{} interrupt state 0x{value:x} @ 0x{guest_physical_address:x}",
                device_loop.name
            ),
            interrupt: None,
        }
    }

    fn block_control_transfer(&self, role: &'static str) -> Result<SoftVmBlockControlTransfer> {
        let artifact = self.find_boot_artifact(role)?;
        let first_block = self.read_boot_artifact_range(role, 0, 8)?;
        Ok(SoftVmBlockControlTransfer {
            role,
            role_code: block_control_role_code(role).unwrap_or_default(),
            first_block_token: padded_le_u64(&first_block),
            byte_len: artifact.byte_len,
            block_count: artifact.block_count.unwrap_or_default(),
            overlay_attached: artifact.overlay.is_some(),
            read_only: artifact.read_only,
        })
    }

    fn block_control_block_token(&self, role: &str, block_index: u64) -> Result<u64> {
        let artifact = self.find_boot_artifact(role)?;
        let block_size = u64::from(artifact.block_size_bytes.ok_or_else(|| {
            PlatformError::conflict(format!("{role} block artifact is missing geometry"))
        })?);
        let block_offset = block_index
            .checked_mul(block_size)
            .ok_or_else(|| PlatformError::invalid(format!("{role} block index overflows")))?;
        let block = self.read_boot_artifact_range(role, block_offset, 8)?;
        Ok(padded_le_u64(&block))
    }

    fn record_secure_boot_semantics(
        &mut self,
        spec: &SoftVmRuntimeSpec,
        stages: &mut Vec<String>,
        console_trace: &mut Vec<String>,
    ) -> Vec<String> {
        if !spec.require_secure_boot {
            return Vec::new();
        }

        stages.push(String::from("secure_boot:policy_enforced"));
        let policy_detail = format!(
            "Software secure boot policy enforced with firmware profile {}",
            spec.reported_firmware_profile()
        );
        console_trace.push(policy_detail.clone());
        self.completed_events.push(SoftVmExecutionEvent::new(
            "secure_boot_policy",
            policy_detail,
        ));

        let boot_device_role = if spec.machine.boot.primary_boot_device == "cdrom" {
            "install_media"
        } else {
            "primary_disk"
        };
        let measurement_roles = [boot_artifact_role(spec), boot_device_role];
        let mut measurements = Vec::new();
        for role in measurement_roles {
            let Some(artifact) = self
                .boot_artifacts
                .iter()
                .find(|artifact| artifact.role == role)
            else {
                continue;
            };
            let measurement = format!("{role}:sha256:{}", artifact.content_fingerprint);
            stages.push(format!("secure_boot:{role}:measured"));
            console_trace.push(format!("Software secure boot measured {measurement}"));
            self.completed_events.push(SoftVmExecutionEvent::new(
                "secure_boot_measurement",
                measurement.clone(),
            ));
            measurements.push(measurement);
        }
        measurements
    }

    fn register_resident_program(
        &mut self,
        name: impl Into<String>,
        mapped_region: impl Into<String>,
        bytecode: Vec<u8>,
    ) -> Result<SoftVmResidentProgram> {
        let program =
            SoftVmResidentProgram::new(name, mapped_region, self.next_program_entry, bytecode);
        self.next_program_entry = self
            .next_program_entry
            .saturating_add(GUEST_PROGRAM_ENTRY_STRIDE);
        self.resident_programs.push(program.clone());
        self.stage_resident_program(&program)?;
        self.index_resident_program(self.resident_programs.len().saturating_sub(1));
        Ok(program)
    }

    fn prepare_direct_kernel_boot(
        &mut self,
        spec: &SoftVmRuntimeSpec,
        artifact_policy: SoftVmArtifactPolicy,
    ) -> Result<()> {
        if !direct_kernel_boot(spec) {
            self.direct_kernel_state = None;
            return Ok(());
        }

        let boot_region = self
            .memory_region_named(boot_code_region_name(spec))?
            .clone();
        let loaded_artifact = load_boot_artifact_preview_with_policy(
            "kernel",
            spec.firmware_artifact_source(),
            artifact_policy,
        )?;
        let preview_byte_len = u64::try_from(loaded_artifact.preview.len())
            .map_err(|_| PlatformError::invalid("kernel preview exceeds u64 addressability"))?;
        if preview_byte_len == 0 {
            return Err(PlatformError::invalid(
                "direct-kernel boot requires a non-empty kernel artifact",
            ));
        }
        let required_boot_bytes =
            DIRECT_KERNEL_IMAGE_GUEST_OFFSET_BYTES.saturating_add(preview_byte_len);
        if required_boot_bytes > boot_region.byte_len {
            return Err(PlatformError::conflict(
                "direct-kernel preview does not fit inside direct_kernel_image region",
            ));
        }

        let kernel_entry_guest_address = boot_region
            .guest_physical_base
            .saturating_add(DIRECT_KERNEL_IMAGE_GUEST_OFFSET_BYTES);
        let kernel_permissions = self
            .guest_memory_permissions_for_region_named(&boot_region.name)?
            .with_execute();
        let kernel_allocation = self.stage_bytes_at_with_permissions(
            String::from("direct_kernel:image"),
            boot_region.name.clone(),
            kernel_entry_guest_address,
            &loaded_artifact.preview,
            kernel_permissions,
        )?;

        let command_line = direct_kernel_command_line(spec);
        let command_line_byte_len = u64::try_from(command_line.len())
            .map_err(|_| PlatformError::invalid("kernel command line exceeds u64"))?;
        let mut command_line_bytes = command_line.as_bytes().to_vec();
        command_line_bytes.push(0);
        let command_line_allocation = self.stage_bytes_at(
            String::from("direct_kernel:cmdline"),
            "guest_ram",
            DIRECT_KERNEL_CMDLINE_GUEST_ADDRESS,
            &command_line_bytes,
        )?;

        let boot_params_manifest = direct_kernel_boot_params_manifest(
            spec,
            spec.firmware_artifact_source(),
            kernel_allocation.guest_address,
            loaded_artifact.byte_len,
            preview_byte_len,
            command_line_allocation.guest_address,
            command_line_byte_len,
        );
        let boot_params_allocation = self.stage_bytes_at(
            String::from("direct_kernel:boot_params"),
            "guest_ram",
            DIRECT_KERNEL_BOOT_PARAMS_GUEST_ADDRESS,
            boot_params_manifest.as_bytes(),
        )?;

        self.next_program_entry = self.next_program_entry.max(align_up_u64(
            boot_region
                .guest_physical_base
                .saturating_add(boot_region.byte_len),
            GUEST_PROGRAM_ENTRY_STRIDE,
        ));
        self.direct_kernel_state = Some(SoftVmDirectKernelBootState {
            kernel_source: spec.firmware_artifact_source().to_owned(),
            kernel_entry_guest_address: kernel_allocation.guest_address,
            kernel_byte_len: loaded_artifact.byte_len,
            preview_byte_len,
            command_line_guest_address: command_line_allocation.guest_address,
            command_line_byte_len,
            boot_params_guest_address: boot_params_allocation.guest_address,
            boot_params_byte_len: boot_params_allocation.byte_len,
            command_line,
        });
        Ok(())
    }

    fn direct_kernel_state(&self) -> Result<&SoftVmDirectKernelBootState> {
        self.direct_kernel_state.as_ref().ok_or_else(|| {
            PlatformError::conflict("software-backed VM has not staged direct-kernel boot state")
        })
    }

    fn stage_resident_program(&mut self, program: &SoftVmResidentProgram) -> Result<()> {
        let permissions = self
            .guest_memory_permissions_for_region_named(&program.mapped_region)?
            .with_execute();
        let _ = self.stage_bytes_at_with_permissions(
            format!("program:{}", program.name),
            program.mapped_region.clone(),
            program.entry_point,
            &program.bytecode,
            permissions,
        )?;
        Ok(())
    }

    fn allocate_guest_data(
        &mut self,
        label: impl Into<String>,
        bytes: &[u8],
    ) -> Result<SoftVmGuestRamAllocation> {
        let guest_address = self.next_guest_data_address;
        let byte_len = u64::try_from(bytes.len()).map_err(|_| {
            PlatformError::invalid("guest data allocation exceeds u64 addressability")
        })?;
        self.next_guest_data_address = self
            .next_guest_data_address
            .saturating_add(align_up_u64(byte_len.max(1), 0x100));
        self.stage_bytes_at(label.into(), "guest_ram", guest_address, bytes)
    }

    fn stage_bytes_at(
        &mut self,
        label: String,
        mapped_region: impl Into<String>,
        guest_address: u64,
        bytes: &[u8],
    ) -> Result<SoftVmGuestRamAllocation> {
        let mapped_region = mapped_region.into();
        let permissions = self.guest_memory_permissions_for_region_named(&mapped_region)?;
        self.stage_bytes_at_with_permissions(
            label,
            mapped_region,
            guest_address,
            bytes,
            permissions,
        )
    }

    fn stage_bytes_at_with_permissions(
        &mut self,
        label: String,
        mapped_region: String,
        guest_address: u64,
        bytes: &[u8],
        permissions: SoftVmGuestMemoryPermissions,
    ) -> Result<SoftVmGuestRamAllocation> {
        let byte_len = u64::try_from(bytes.len())
            .map_err(|_| PlatformError::invalid("guest allocation length exceeds u64"))?;
        self.clear_allocation(&label);
        let touched_pages = guest_pages_for_span(guest_address, byte_len);
        for (offset, byte) in bytes.iter().enumerate() {
            let guest_offset = u64::try_from(offset).map_err(|_| {
                PlatformError::invalid("guest memory write offset exceeds u64 addressability")
            })?;
            self.guest_memory_bytes.write_byte(
                guest_address.saturating_add(guest_offset),
                *byte,
                permissions,
                SoftVmGuestMemoryWriteOrigin::HostStage,
            )?;
        }
        self.invalidate_decoded_blocks_for_pages(&touched_pages);
        let allocation = SoftVmGuestRamAllocation {
            label,
            mapped_region,
            guest_address,
            byte_len,
        };
        self.guest_ram_allocations.push(allocation.clone());
        self.guest_ram_allocations.sort_by(|left, right| {
            left.guest_address
                .cmp(&right.guest_address)
                .then(left.label.cmp(&right.label))
        });
        Ok(allocation)
    }

    fn clear_allocation(&mut self, label: &str) {
        if let Some(index) = self
            .guest_ram_allocations
            .iter()
            .position(|allocation| allocation.label == label)
        {
            let allocation = self.guest_ram_allocations.remove(index);
            let touched_pages = guest_pages_for_span(allocation.guest_address, allocation.byte_len);
            for offset in 0..allocation.byte_len {
                let address = allocation.guest_address.saturating_add(offset);
                let _ = self
                    .guest_memory_bytes
                    .remove_byte(address, SoftVmGuestMemoryWriteOrigin::HostStage);
            }
            self.invalidate_decoded_blocks_for_pages(&touched_pages);
        }
    }

    fn rebuild_executable_page_lookup(&mut self) {
        self.executable_page_lookup.clear();
        for resident_program_index in 0..self.resident_programs.len() {
            self.index_resident_program(resident_program_index);
        }
    }

    fn index_resident_program(&mut self, resident_program_index: usize) {
        let Some(program) = self.resident_programs.get(resident_program_index) else {
            return;
        };
        let byte_len = u64::try_from(program.bytecode.len()).unwrap_or(u64::MAX);
        let guest_end_address = program.entry_point.saturating_add(byte_len);
        let range = SoftVmResidentProgramRange {
            resident_program_index,
            guest_start_address: program.entry_point,
            guest_end_address,
        };
        for page_index in guest_pages_for_span(program.entry_point, byte_len) {
            let entries = self.executable_page_lookup.entry(page_index).or_default();
            entries.retain(|entry| entry.resident_program_index != resident_program_index);
            entries.push(range);
            entries.sort_by(|left, right| {
                left.guest_start_address
                    .cmp(&right.guest_start_address)
                    .then(left.guest_end_address.cmp(&right.guest_end_address))
                    .then(
                        left.resident_program_index
                            .cmp(&right.resident_program_index),
                    )
            });
        }
    }

    fn invalidate_decoded_blocks_for_pages(&mut self, page_indices: &[u64]) {
        let block_starts = page_indices
            .iter()
            .filter_map(|page_index| self.decoded_block_pages.get(page_index))
            .flat_map(|starts| starts.iter().copied())
            .collect::<BTreeSet<_>>();
        for block_start in block_starts {
            if self.remove_decoded_block_cache_entry(block_start).is_some() {
                self.dbt_stats.decoded_block_invalidations =
                    self.dbt_stats.decoded_block_invalidations.saturating_add(1);
            }
        }
    }

    fn remove_decoded_block_cache_entry(&mut self, block_start: u64) -> Option<SoftVmDecodedBlock> {
        let cached = self.decoded_block_cache.remove(&block_start)?;
        for stamp in &cached.page_generations {
            let should_remove_page =
                if let Some(block_starts) = self.decoded_block_pages.get_mut(&stamp.page_index) {
                    let _ = block_starts.remove(&block_start);
                    block_starts.is_empty()
                } else {
                    false
                };
            if should_remove_page {
                let _ = self.decoded_block_pages.remove(&stamp.page_index);
            }
        }
        Some(cached)
    }

    fn remember_decoded_block(&mut self, block: SoftVmDecodedBlock) {
        let _ = self.remove_decoded_block_cache_entry(block.start_guest_address);
        for stamp in &block.page_generations {
            self.decoded_block_pages
                .entry(stamp.page_index)
                .or_default()
                .insert(block.start_guest_address);
        }
        self.decoded_block_cache
            .insert(block.start_guest_address, block);
    }

    fn guest_memory_slice(&self, guest_address: u64, byte_len: u64) -> Vec<u8> {
        (0..byte_len)
            .map(|offset| {
                let address = guest_address.saturating_add(offset);
                self.guest_memory_bytes.get(&address).copied().unwrap_or(0)
            })
            .collect::<Vec<_>>()
    }

    fn resident_program_named(&self, name: &str) -> Result<&SoftVmResidentProgram> {
        self.resident_programs
            .iter()
            .find(|program| program.name == name)
            .ok_or_else(|| PlatformError::unavailable(format!("missing resident program `{name}`")))
    }

    fn prepare_program_execution(&mut self, entry_point: u64) {
        self.cpu_state.instruction_pointer = entry_point;
        self.cpu_state.general_purpose_registers = [0; 4];
        self.cpu_state.call_depth = 0;
        self.cpu_state.trap_frame_depth = 0;
        self.cpu_state.faulted = false;
        self.cpu_state.fault_vector = None;
        self.cpu_state.fault_detail = None;
        self.cpu_state.halted = false;
    }

    fn resident_program_range_for_address(
        &self,
        guest_address: u64,
    ) -> Option<SoftVmResidentProgramRange> {
        self.executable_page_lookup
            .get(&guest_page_index(guest_address))
            .and_then(|entries| {
                entries.iter().copied().find(|entry| {
                    guest_address >= entry.guest_start_address
                        && guest_address < entry.guest_end_address
                })
            })
    }

    fn resident_program_containing_with_fault(
        &mut self,
        guest_address: u64,
    ) -> Result<SoftVmResidentProgram> {
        self.resident_program_containing(guest_address)
            .cloned()
            .or_else(|_| self.fast_instruction_fetch_fault(guest_address))
    }

    fn fast_fault_lookup_kind(&mut self, guest_address: u64) -> SoftVmFaultLookupKind {
        self.dbt_stats.fast_fault_lookups = self.dbt_stats.fast_fault_lookups.saturating_add(1);
        match self.guest_memory_bytes.page(guest_address) {
            Some(page) if page.permissions.executable => SoftVmFaultLookupKind::ExecutableGap,
            Some(_) => SoftVmFaultLookupKind::MappedNonExecutable,
            None => SoftVmFaultLookupKind::Unmapped,
        }
    }

    fn fast_instruction_fetch_fault<T>(&mut self, guest_address: u64) -> Result<T> {
        let (vector, detail) = match self.fast_fault_lookup_kind(guest_address) {
            SoftVmFaultLookupKind::ExecutableGap => (
                0x06,
                format!("guest instruction fetch entered an executable gap at 0x{guest_address:x}"),
            ),
            SoftVmFaultLookupKind::MappedNonExecutable => (
                0x0e,
                format!(
                    "guest instruction fetch at 0x{guest_address:x} violates execute permission"
                ),
            ),
            SoftVmFaultLookupKind::Unmapped => (
                0x06,
                format!("guest ISA ended before byte at 0x{guest_address:x} could be read"),
            ),
        };
        self.raise_fault(vector, detail)
    }

    fn decode_instruction_byte_at(
        &mut self,
        guest_address: u64,
        touched_pages: &mut BTreeSet<u64>,
    ) -> Result<u8> {
        if let Some(page) = self.guest_memory_bytes.page(guest_address)
            && (!page.permissions.readable || !page.permissions.executable)
        {
            return self.raise_fault(
                0x0e,
                format!(
                    "guest instruction fetch at 0x{guest_address:x} violates execute permission"
                ),
            );
        }
        let Some(value) = self.guest_memory_bytes.get(&guest_address).copied() else {
            return self.fast_instruction_fetch_fault(guest_address);
        };
        let _ = touched_pages.insert(guest_page_index(guest_address));
        Ok(value)
    }

    fn decode_instruction_u64_at(
        &mut self,
        guest_address: u64,
        touched_pages: &mut BTreeSet<u64>,
    ) -> Result<u64> {
        let mut bytes = [0u8; 8];
        for (offset, slot) in bytes.iter_mut().enumerate() {
            let guest_offset = u64::try_from(offset).map_err(|_| {
                PlatformError::invalid("guest instruction offset exceeds u64 addressability")
            })?;
            *slot = self.decode_instruction_byte_at(
                guest_address.saturating_add(guest_offset),
                touched_pages,
            )?;
        }
        Ok(u64::from_le_bytes(bytes))
    }

    fn decoded_block_for_address(&mut self, guest_address: u64) -> Result<SoftVmDecodedBlock> {
        if let Some(cached) = self.decoded_block_cache.get(&guest_address).cloned() {
            if cached.is_current(self) {
                self.dbt_stats.decoded_block_cache_hits =
                    self.dbt_stats.decoded_block_cache_hits.saturating_add(1);
                return Ok(cached);
            }
            let _ = self.remove_decoded_block_cache_entry(guest_address);
        }
        self.dbt_stats.decoded_block_cache_misses =
            self.dbt_stats.decoded_block_cache_misses.saturating_add(1);
        let decoded = self.decode_block(guest_address)?;
        self.remember_decoded_block(decoded.clone());
        Ok(decoded)
    }

    fn decode_block(&mut self, guest_address: u64) -> Result<SoftVmDecodedBlock> {
        let program = self.resident_program_containing_with_fault(guest_address)?;
        let program_end = program
            .entry_point
            .saturating_add(u64::try_from(program.bytecode.len()).unwrap_or(u64::MAX));
        let mut cursor = guest_address;
        let mut touched_pages = BTreeSet::new();
        let mut instructions = Vec::new();
        while cursor < program_end {
            let opcode = self.decode_instruction_byte_at(cursor, &mut touched_pages)?;
            let instruction = match opcode {
                ISA_OPCODE_MOV_IMM64 => SoftVmDecodedInstruction::MovImm64 {
                    guest_address: cursor,
                    next_guest_address: cursor.saturating_add(10),
                    register: self
                        .decode_instruction_byte_at(cursor.saturating_add(1), &mut touched_pages)?,
                    immediate: self
                        .decode_instruction_u64_at(cursor.saturating_add(2), &mut touched_pages)?,
                },
                ISA_OPCODE_CALL_ABS64 => SoftVmDecodedInstruction::CallAbs64 {
                    guest_address: cursor,
                    next_guest_address: cursor.saturating_add(9),
                    target: self
                        .decode_instruction_u64_at(cursor.saturating_add(1), &mut touched_pages)?,
                },
                ISA_OPCODE_RET => SoftVmDecodedInstruction::Ret {
                    guest_address: cursor,
                    next_guest_address: cursor.saturating_add(1),
                },
                ISA_OPCODE_MMIO_WRITE64 => SoftVmDecodedInstruction::MmioWrite64 {
                    guest_address: cursor,
                    next_guest_address: cursor.saturating_add(17),
                    guest_physical_address: self
                        .decode_instruction_u64_at(cursor.saturating_add(1), &mut touched_pages)?,
                    value: self
                        .decode_instruction_u64_at(cursor.saturating_add(9), &mut touched_pages)?,
                },
                ISA_OPCODE_MMIO_READ64 => SoftVmDecodedInstruction::MmioRead64 {
                    guest_address: cursor,
                    next_guest_address: cursor.saturating_add(10),
                    register: self
                        .decode_instruction_byte_at(cursor.saturating_add(1), &mut touched_pages)?,
                    guest_physical_address: self
                        .decode_instruction_u64_at(cursor.saturating_add(2), &mut touched_pages)?,
                },
                ISA_OPCODE_NATIVE_CALL => SoftVmDecodedInstruction::NativeCall {
                    guest_address: cursor,
                    next_guest_address: cursor.saturating_add(2),
                    call_id: self
                        .decode_instruction_byte_at(cursor.saturating_add(1), &mut touched_pages)?,
                },
                ISA_OPCODE_HALT => SoftVmDecodedInstruction::Halt {
                    guest_address: cursor,
                    next_guest_address: cursor.saturating_add(1),
                },
                _ => {
                    return self.raise_fault(
                        0x06,
                        format!("unsupported guest-isa opcode `0x{opcode:02x}`"),
                    );
                }
            };
            cursor = instruction.next_guest_address();
            let terminates_block = instruction.terminates_block();
            instructions.push(instruction);
            if terminates_block {
                break;
            }
        }
        let page_generations = touched_pages
            .into_iter()
            .map(|page_index| SoftVmPageGenerationStamp {
                page_index,
                generation: self
                    .guest_memory_bytes
                    .page(guest_page_base(page_index))
                    .map(|page| page.generation)
                    .unwrap_or_default(),
            })
            .collect::<Vec<_>>();
        Ok(SoftVmDecodedBlock {
            program_name: program.name,
            start_guest_address: guest_address,
            page_generations,
            instructions,
        })
    }

    fn native_call_trace_detail(
        &self,
        execution_kind: SoftVmProgramExecutionKind,
        call_id: u8,
    ) -> Result<String> {
        match execution_kind {
            SoftVmProgramExecutionKind::Boot => {
                let boot_stage =
                    u8::try_from(self.read_register(ISA_REGISTER_ARG1)?).map_err(|_| {
                        PlatformError::invalid("boot-service stage register exceeds u8")
                    })?;
                Ok(format!(
                    "native call {} via {}",
                    native_call_name(call_id),
                    native_call_name(boot_stage)
                ))
            }
            SoftVmProgramExecutionKind::Guest => {
                let service_kind =
                    u8::try_from(self.read_register(ISA_REGISTER_ARG1)?).map_err(|_| {
                        PlatformError::invalid("guest-kernel service kind register exceeds u8")
                    })?;
                let service_route =
                    u8::try_from(self.read_register(ISA_REGISTER_ARG2)?).map_err(|_| {
                        PlatformError::invalid("guest-kernel service route register exceeds u8")
                    })?;
                Ok(format!(
                    "native call {} via {}:{}",
                    native_call_name(call_id),
                    guest_kernel_service_kind_name(service_kind),
                    guest_kernel_service_route_name(service_route)
                ))
            }
        }
    }

    fn execute_program_blocks<F>(
        &mut self,
        execution_kind: SoftVmProgramExecutionKind,
        outcome: &mut SoftVmProgramOutcome,
        native_call: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&mut Self, u8, &mut SoftVmProgramOutcome) -> Result<()>,
    {
        if !self
            .guest_memory_bytes
            .contains_key(&self.cpu_state.instruction_pointer)
        {
            return Ok(());
        }
        let mut next_block =
            Some(self.decoded_block_for_address(self.cpu_state.instruction_pointer)?);
        while let Some(block) = next_block {
            let Some(next_guest_address) =
                self.execute_decoded_block(execution_kind, &block, outcome, native_call)?
            else {
                break;
            };
            if !self.guest_memory_bytes.contains_key(&next_guest_address) {
                break;
            }
            let chained_block = self.decoded_block_for_address(next_guest_address)?;
            self.dbt_stats.trace_chain_hits = self.dbt_stats.trace_chain_hits.saturating_add(1);
            next_block = Some(chained_block);
        }
        Ok(())
    }

    fn execute_decoded_block<F>(
        &mut self,
        execution_kind: SoftVmProgramExecutionKind,
        block: &SoftVmDecodedBlock,
        outcome: &mut SoftVmProgramOutcome,
        native_call: &mut F,
    ) -> Result<Option<u64>>
    where
        F: FnMut(&mut Self, u8, &mut SoftVmProgramOutcome) -> Result<()>,
    {
        let mut next_guest_address = self.cpu_state.instruction_pointer;
        for instruction in &block.instructions {
            match *instruction {
                SoftVmDecodedInstruction::MovImm64 {
                    guest_address,
                    next_guest_address: next_ip,
                    register,
                    immediate,
                } => {
                    self.write_register(register, immediate)?;
                    self.record_trace_for_program_name(
                        block.program_name.as_str(),
                        guest_address,
                        ISA_OPCODE_MOV_IMM64,
                        format!("mov {}, 0x{immediate:x}", guest_isa_register_name(register)),
                    );
                    self.cpu_state.instruction_pointer = next_ip;
                    self.advance_guest_instruction(outcome);
                    next_guest_address = next_ip;
                }
                SoftVmDecodedInstruction::CallAbs64 {
                    guest_address,
                    next_guest_address: next_ip,
                    target,
                } => {
                    self.record_trace_for_program_name(
                        block.program_name.as_str(),
                        guest_address,
                        ISA_OPCODE_CALL_ABS64,
                        format!("call 0x{target:x}"),
                    );
                    self.cpu_state.instruction_pointer = next_ip;
                    self.push_guest_stack_u64(next_ip)?;
                    self.advance_guest_instruction(outcome);
                    self.cpu_state.instruction_pointer = target;
                    return Ok(Some(target));
                }
                SoftVmDecodedInstruction::Ret {
                    guest_address,
                    next_guest_address: next_ip,
                } => {
                    self.cpu_state.instruction_pointer = next_ip;
                    let return_address = self.pop_guest_stack_u64()?;
                    self.record_trace_for_program_name(
                        block.program_name.as_str(),
                        guest_address,
                        ISA_OPCODE_RET,
                        format!("ret 0x{return_address:x}"),
                    );
                    self.advance_guest_instruction(outcome);
                    self.cpu_state.instruction_pointer = return_address;
                    return Ok(Some(return_address));
                }
                SoftVmDecodedInstruction::MmioWrite64 {
                    guest_address,
                    next_guest_address: next_ip,
                    guest_physical_address,
                    value,
                } => {
                    let detail = self.dispatch_mmio_write(guest_physical_address, value, None)?;
                    self.record_trace_for_program_name(
                        block.program_name.as_str(),
                        guest_address,
                        ISA_OPCODE_MMIO_WRITE64,
                        detail,
                    );
                    self.cpu_state.instruction_pointer = next_ip;
                    self.advance_guest_instruction(outcome);
                    next_guest_address = next_ip;
                }
                SoftVmDecodedInstruction::MmioRead64 {
                    guest_address,
                    next_guest_address: next_ip,
                    register,
                    guest_physical_address,
                } => {
                    let (value, detail) = self.dispatch_mmio_read(guest_physical_address)?;
                    self.write_register(register, value)?;
                    self.record_trace_for_program_name(
                        block.program_name.as_str(),
                        guest_address,
                        ISA_OPCODE_MMIO_READ64,
                        format!("{detail} into {}", guest_isa_register_name(register)),
                    );
                    self.cpu_state.instruction_pointer = next_ip;
                    self.advance_guest_instruction(outcome);
                    next_guest_address = next_ip;
                }
                SoftVmDecodedInstruction::NativeCall {
                    guest_address,
                    next_guest_address: next_ip,
                    call_id,
                } => {
                    self.cpu_state.instruction_pointer = next_ip;
                    self.record_trace_for_program_name(
                        block.program_name.as_str(),
                        guest_address,
                        call_id,
                        self.native_call_trace_detail(execution_kind, call_id)?,
                    );
                    self.advance_guest_instruction(outcome);
                    native_call(self, call_id, outcome)?;
                    return Ok(Some(self.cpu_state.instruction_pointer));
                }
                SoftVmDecodedInstruction::Halt {
                    guest_address,
                    next_guest_address: next_ip,
                } => {
                    self.record_trace_for_program_name(
                        block.program_name.as_str(),
                        guest_address,
                        ISA_OPCODE_HALT,
                        match execution_kind {
                            SoftVmProgramExecutionKind::Boot => {
                                String::from("boot guest-isa halted")
                            }
                            SoftVmProgramExecutionKind::Guest => {
                                String::from("guest command guest-isa halted")
                            }
                        },
                    );
                    self.cpu_state.instruction_pointer = next_ip;
                    self.cpu_state.halted = true;
                    return Ok(None);
                }
            }
        }
        Ok(Some(next_guest_address))
    }

    fn execute_boot_program(&mut self, spec: &SoftVmRuntimeSpec) -> Result<SoftVmProgramOutcome> {
        let program = self.resident_program_named("boot_dispatch")?.clone();
        self.prepare_program_execution(program.entry_point);
        let mut outcome = SoftVmProgramOutcome::default();
        self.execute_program_blocks(
            SoftVmProgramExecutionKind::Boot,
            &mut outcome,
            &mut |execution, call_id, outcome| match call_id {
                NATIVE_CALL_BOOT_SERVICE_ROUTE => {
                    execution.execute_boot_service_route(spec, outcome)
                }
                _ => Err(PlatformError::invalid(format!(
                    "unsupported boot native call `0x{call_id:02x}`"
                ))),
            },
        )?;
        Ok(outcome)
    }

    fn execute_boot_service_route(
        &mut self,
        spec: &SoftVmRuntimeSpec,
        outcome: &mut SoftVmProgramOutcome,
    ) -> Result<()> {
        let dispatch = BootServiceDispatchIntent::decode(self)?;
        dispatch.record_trace(self)?;
        dispatch.dispatch(self, spec, outcome)
    }

    fn complete_boot_stage(
        &mut self,
        outcome: &mut SoftVmProgramOutcome,
        event_kind: &'static str,
        detail: String,
        stage_marker: String,
        console_line: String,
        guest_control_ready: bool,
    ) {
        self.completed_events
            .push(SoftVmExecutionEvent::new(event_kind, detail));
        outcome.stages.push(stage_marker);
        outcome.console_trace.push(console_line);
        if guest_control_ready {
            outcome.guest_control_ready = true;
        }
    }

    fn execute_guest_program(
        &mut self,
        program: &SoftVmResidentProgram,
        _guest_architecture: &str,
        vcpu: u16,
        guest_memory_bytes: u64,
        control: &mut SoftVmGuestControl,
    ) -> Result<SoftVmProgramOutcome> {
        self.prepare_program_execution(program.entry_point);
        write_guest_kernel_files(self, &mut control.files, "", 0, "", "")?;
        let mut outcome = SoftVmProgramOutcome::default();
        self.execute_program_blocks(
            SoftVmProgramExecutionKind::Guest,
            &mut outcome,
            &mut |execution, call_id, _outcome| match call_id {
                NATIVE_CALL_GUEST_SERVICE_ROUTE => {
                    execution.execute_guest_kernel_service_route(control, vcpu, guest_memory_bytes)
                }
                _ => execution.raise_fault(
                    0x06,
                    format!("unsupported guest native call `0x{call_id:02x}`"),
                ),
            },
        )?;
        self.refresh_guest_program_outcome(control, &mut outcome)?;
        let timer_vector = self.interrupt_vector_for_source("virt_timer", 0x20);
        self.record_timer_signal(u64::from(timer_vector));
        self.queue_interrupt(
            timer_vector,
            "virt_timer",
            format!(
                "guest program `{}` completed at instruction pointer 0x{:x}",
                program.name, self.cpu_state.instruction_pointer
            ),
        );
        Ok(outcome)
    }

    fn execute_guest_kernel_service_route(
        &mut self,
        control: &mut SoftVmGuestControl,
        vcpu: u16,
        guest_memory_bytes: u64,
    ) -> Result<()> {
        let dispatch = GuestKernelDispatchIntent::decode(self, vcpu, guest_memory_bytes)?;
        dispatch.record_trace(self)?;
        dispatch.dispatch(self, control)
    }

    fn write_guest_kernel_result(
        &mut self,
        control: &mut SoftVmGuestControl,
        operation_name: &str,
        exit_code: i32,
        stdout: &str,
        stderr: &str,
    ) -> Result<()> {
        write_guest_kernel_files(
            self,
            &mut control.files,
            operation_name,
            exit_code,
            stdout,
            stderr,
        )
    }

    fn write_guest_kernel_success_empty(
        &mut self,
        control: &mut SoftVmGuestControl,
        operation_name: &str,
    ) -> Result<()> {
        self.write_guest_kernel_result(control, operation_name, 0, "", "")
    }

    fn write_guest_kernel_missing_result(
        &mut self,
        control: &mut SoftVmGuestControl,
        operation_name: &str,
        exit_code: i32,
        stderr: String,
    ) -> Result<()> {
        self.write_guest_kernel_result(control, operation_name, exit_code, "", &stderr)
    }

    fn write_guest_kernel_file_lookup_result(
        &mut self,
        control: &mut SoftVmGuestControl,
        operation_name: &str,
        lookup: &GuestKernelResolvedLookup,
        missing: GuestKernelLookupMissingBehavior,
    ) -> Result<()> {
        match read_guest_file(self, control, &lookup.lookup_path) {
            Some(stdout) if !missing.treat_empty_as_missing || !stdout.trim().is_empty() => {
                self.write_guest_kernel_result(control, operation_name, 0, &stdout, "")
            }
            None => self.write_guest_kernel_missing_result(
                control,
                operation_name,
                missing.exit_code,
                (missing.stderr)(lookup.subject.as_str()),
            ),
            Some(_) => self.write_guest_kernel_missing_result(
                control,
                operation_name,
                missing.exit_code,
                (missing.stderr)(lookup.subject.as_str()),
            ),
        }
    }

    fn execute_guest_kernel_mutation_route(
        &mut self,
        control: &mut SoftVmGuestControl,
        invocation: &GuestKernelRouteInvocation,
        behavior: GuestKernelMutationBehavior,
    ) -> Result<()> {
        let path = invocation.read_arg0(self)?;
        match behavior {
            GuestKernelMutationBehavior::WritePayloadWithTrailingNewline => {
                let payload = invocation.read_arg1(self)?;
                upsert_guest_file(self, &mut control.files, path, format!("{payload}\n"))?;
            }
            GuestKernelMutationBehavior::TouchIfMissing => {
                if read_guest_file(self, control, &path).is_none() {
                    upsert_guest_file(self, &mut control.files, path, String::new())?;
                }
            }
        }
        refresh_guest_network_views(self, &mut control.files, &control.hostname)?;
        self.write_guest_kernel_success_empty(control, invocation.operation_name.as_str())
    }

    fn execute_guest_route_unixbench(
        &mut self,
        control: &mut SoftVmGuestControl,
        invocation: &GuestKernelRouteInvocation,
    ) -> Result<()> {
        let metrics = native_unixbench_metrics(invocation.vcpu, invocation.guest_memory_bytes);
        control.benchmark_runs = control.benchmark_runs.saturating_add(1);
        let run_id = control.benchmark_runs;
        upsert_guest_file_batch(
            self,
            &mut control.files,
            unixbench_metric_projections(&metrics),
        )?;
        let summary = render_unixbench_summary_from_guest_metrics(self, control)?;
        let score = metrics.index;
        upsert_guest_file_batch(
            self,
            &mut control.files,
            unixbench_artifact_projections(run_id, score, &summary),
        )?;
        self.write_guest_kernel_result(control, invocation.operation_name.as_str(), 0, &summary, "")
    }

    fn execute_guest_route_error(
        &mut self,
        control: &mut SoftVmGuestControl,
        invocation: &GuestKernelRouteInvocation,
    ) -> Result<()> {
        let message = invocation.read_arg0(self)?;
        self.write_guest_kernel_result(
            control,
            invocation.operation_name.as_str(),
            127,
            "",
            &format!("{message}\n"),
        )
    }

    fn execute_guest_route_http_fetch(
        &mut self,
        control: &mut SoftVmGuestControl,
        invocation: &GuestKernelRouteInvocation,
    ) -> Result<()> {
        let url = invocation.read_arg0(self)?;
        let method = GuestEgressMethod::parse(invocation.read_arg1(self)?.as_str())?;
        // The software_dbt path now exposes a guest-owned usernet-style NAT
        // contract, but the data plane still rides host sockets behind the
        // synthetic guest network state and durable command semantics.
        match guest_egress_fetch(url.as_str(), method) {
            Ok(response) => {
                let stdout = if method == GuestEgressMethod::Head {
                    response.headers_text.clone()
                } else {
                    response.body_text.clone()
                };
                upsert_guest_file_batch(
                    self,
                    &mut control.files,
                    guest_egress_result_projections(&response),
                )?;
                self.completed_events.push(SoftVmExecutionEvent::new(
                    "guest_egress_fetch",
                    format!(
                        "{} {} -> {}",
                        method.as_str(),
                        response.url,
                        response.http_status
                    ),
                ));
                self.write_guest_kernel_result(
                    control,
                    invocation.operation_name.as_str(),
                    0,
                    &stdout,
                    "",
                )
            }
            Err(failure) => {
                self.completed_events.push(SoftVmExecutionEvent::new(
                    "guest_egress_fetch_failed",
                    format!("{} {} -> {}", method.as_str(), url, failure.stderr.trim()),
                ));
                self.write_guest_kernel_result(
                    control,
                    invocation.operation_name.as_str(),
                    failure.exit_code,
                    "",
                    &failure.stderr,
                )
            }
        }
    }

    fn execute_guest_route_tcp_connect(
        &mut self,
        control: &mut SoftVmGuestControl,
        invocation: &GuestKernelRouteInvocation,
    ) -> Result<()> {
        let target = invocation.read_arg0(self)?;
        let request = parse_guest_tcp_wire_request(invocation.read_arg1(self)?.as_str())?;
        match guest_tcp_connect(target.as_str(), &request) {
            Ok(response) => {
                upsert_guest_file_batch(
                    self,
                    &mut control.files,
                    guest_tcp_result_projections(&response),
                )?;
                self.completed_events.push(SoftVmExecutionEvent::new(
                    "guest_tcp_connect",
                    format!(
                        "{} -> sent={} recv={}",
                        response.target, response.bytes_sent, response.bytes_received
                    ),
                ));
                self.write_guest_kernel_result(
                    control,
                    invocation.operation_name.as_str(),
                    0,
                    &response.stdout,
                    "",
                )
            }
            Err(failure) => {
                self.completed_events.push(SoftVmExecutionEvent::new(
                    "guest_tcp_connect_failed",
                    format!("{} -> {}", target, failure.stderr.trim()),
                ));
                self.write_guest_kernel_result(
                    control,
                    invocation.operation_name.as_str(),
                    failure.exit_code,
                    "",
                    &failure.stderr,
                )
            }
        }
    }

    fn execute_guest_route_dns_lookup(
        &mut self,
        control: &mut SoftVmGuestControl,
        invocation: &GuestKernelRouteInvocation,
    ) -> Result<()> {
        let host = invocation.read_arg0(self)?;
        let mode = match invocation.read_arg1(self)?.as_str() {
            "nslookup" => GuestDnsLookupMode::Nslookup,
            "getent_hosts" => GuestDnsLookupMode::GetentHosts,
            _ => {
                return Err(PlatformError::invalid(
                    "guest dns lookup mode must be `nslookup` or `getent_hosts`",
                ));
            }
        };
        match guest_dns_lookup(mode, host.as_str()) {
            Ok(response) => {
                self.completed_events.push(SoftVmExecutionEvent::new(
                    "guest_dns_lookup",
                    format!("{} -> {}", host, response.resolved_addresses.join(",")),
                ));
                self.write_guest_kernel_result(
                    control,
                    invocation.operation_name.as_str(),
                    0,
                    &response.stdout,
                    "",
                )
            }
            Err(failure) => {
                self.completed_events.push(SoftVmExecutionEvent::new(
                    "guest_dns_lookup_failed",
                    format!("{} -> {}", host, failure.stderr.trim()),
                ));
                self.write_guest_kernel_result(
                    control,
                    invocation.operation_name.as_str(),
                    failure.exit_code,
                    "",
                    &failure.stderr,
                )
            }
        }
    }

    fn execute_guest_route_udp_exchange(
        &mut self,
        control: &mut SoftVmGuestControl,
        invocation: &GuestKernelRouteInvocation,
    ) -> Result<()> {
        let target = invocation.read_arg0(self)?;
        let request = parse_guest_udp_wire_request(invocation.read_arg1(self)?.as_str())?;
        match guest_udp_exchange(target.as_str(), &request) {
            Ok(response) => {
                upsert_guest_file_batch(
                    self,
                    &mut control.files,
                    guest_udp_result_projections(&response),
                )?;
                self.completed_events.push(SoftVmExecutionEvent::new(
                    "guest_udp_exchange",
                    format!(
                        "{} -> sent={} recv={}",
                        response.target, response.bytes_sent, response.bytes_received
                    ),
                ));
                self.write_guest_kernel_result(
                    control,
                    invocation.operation_name.as_str(),
                    0,
                    &response.stdout,
                    "",
                )
            }
            Err(failure) => {
                self.completed_events.push(SoftVmExecutionEvent::new(
                    "guest_udp_exchange_failed",
                    format!("{} -> {}", target, failure.stderr.trim()),
                ));
                self.write_guest_kernel_result(
                    control,
                    invocation.operation_name.as_str(),
                    failure.exit_code,
                    "",
                    &failure.stderr,
                )
            }
        }
    }

    fn resident_program_containing(&self, guest_address: u64) -> Result<&SoftVmResidentProgram> {
        if let Some(entry) = self.resident_program_range_for_address(guest_address)
            && let Some(program) = self.resident_programs.get(entry.resident_program_index)
        {
            let byte_len = u64::try_from(program.bytecode.len()).unwrap_or(u64::MAX);
            if guest_address >= program.entry_point
                && guest_address < program.entry_point.saturating_add(byte_len)
            {
                return Ok(program);
            }
        }
        self.resident_programs
            .iter()
            .find(|program| {
                let byte_len = u64::try_from(program.bytecode.len()).unwrap_or(u64::MAX);
                guest_address >= program.entry_point
                    && guest_address < program.entry_point.saturating_add(byte_len)
            })
            .ok_or_else(|| {
                PlatformError::unavailable(format!(
                    "missing resident program covering guest address 0x{guest_address:x}"
                ))
            })
    }

    fn mmio_region_for_address(&self, guest_physical_address: u64) -> Result<&SoftVmMmioRegion> {
        self.mmio_regions
            .iter()
            .find(|region| {
                guest_physical_address >= region.guest_physical_base
                    && guest_physical_address
                        < region.guest_physical_base.saturating_add(region.byte_len)
            })
            .ok_or_else(|| {
                PlatformError::invalid(format!(
                    "guest MMIO address 0x{guest_physical_address:x} is unmapped"
                ))
            })
    }

    fn mmio_region_named(&self, region_name: &str) -> Option<&SoftVmMmioRegion> {
        self.mmio_regions
            .iter()
            .find(|region| region.name == region_name)
    }

    fn memory_region_named(&self, region_name: &str) -> Result<&SoftVmMemoryRegion> {
        self.memory_regions
            .iter()
            .find(|region| region.name == region_name)
            .ok_or_else(|| {
                PlatformError::invalid(format!("guest memory region `{region_name}` is undefined"))
            })
    }

    fn memory_region_for_address(
        &self,
        guest_physical_address: u64,
    ) -> Result<&SoftVmMemoryRegion> {
        self.memory_regions
            .iter()
            .find(|region| {
                guest_physical_address >= region.guest_physical_base
                    && guest_physical_address
                        < region.guest_physical_base.saturating_add(region.byte_len)
            })
            .ok_or_else(|| {
                PlatformError::invalid(format!(
                    "guest memory address 0x{guest_physical_address:x} is unmapped"
                ))
            })
    }

    fn guest_memory_permissions_for_region_named(
        &self,
        region_name: &str,
    ) -> Result<SoftVmGuestMemoryPermissions> {
        self.memory_region_named(region_name)
            .map(SoftVmGuestMemoryPermissions::from_region)
    }

    fn guest_memory_permissions_for_address(
        &self,
        guest_physical_address: u64,
    ) -> Result<SoftVmGuestMemoryPermissions> {
        self.memory_region_for_address(guest_physical_address)
            .map(SoftVmGuestMemoryPermissions::from_region)
    }

    fn write_guest_runtime_byte(&mut self, guest_address: u64, value: u8) -> Result<()> {
        let permissions = match self.guest_memory_permissions_for_address(guest_address) {
            Ok(permissions) => permissions,
            Err(error) => return self.raise_fault(0x0e, error.message),
        };
        if let Err(error) = self.guest_memory_bytes.write_byte(
            guest_address,
            value,
            permissions,
            SoftVmGuestMemoryWriteOrigin::GuestStore,
        ) {
            return self.raise_fault(0x0e, error.message);
        }
        self.invalidate_decoded_blocks_for_pages(&[guest_page_index(guest_address)]);
        Ok(())
    }

    fn clear_guest_runtime_byte(&mut self, guest_address: u64) -> Result<()> {
        if let Err(error) = self
            .guest_memory_bytes
            .remove_byte(guest_address, SoftVmGuestMemoryWriteOrigin::GuestStore)
        {
            return self.raise_fault(0x0e, error.message);
        }
        self.invalidate_decoded_blocks_for_pages(&[guest_page_index(guest_address)]);
        Ok(())
    }

    fn device_loop_mut_by_region(&mut self, region_name: &str) -> Option<&mut SoftVmDeviceLoop> {
        self.device_loops
            .iter_mut()
            .find(|device_loop| device_loop.region_name == region_name)
    }

    fn device_loop_by_name(&self, name: &str) -> Option<&SoftVmDeviceLoop> {
        self.device_loops
            .iter()
            .find(|device_loop| device_loop.name == name)
    }

    fn device_loop_mut_by_name(&mut self, name: &str) -> Option<&mut SoftVmDeviceLoop> {
        self.device_loops
            .iter_mut()
            .find(|device_loop| device_loop.name == name)
    }

    fn handle_block_control_mmio_write(
        &mut self,
        device_loop_index: usize,
        guest_physical_address: u64,
        value: u64,
    ) -> SoftVmDeviceMmioEffect {
        let offset = self
            .mmio_region_named(self.device_loops[device_loop_index].region_name.as_str())
            .map(|region| guest_physical_address.saturating_sub(region.guest_physical_base))
            .unwrap_or_default();
        let interrupt_vector = self.device_loops[device_loop_index].interrupt_vector;
        {
            let device_loop = &mut self.device_loops[device_loop_index];
            if let Some(queue) = device_loop.queue_mut("requests") {
                queue.pending.push(value);
                let drained = queue.pending.remove(0);
                queue.completed.push(drained);
            }
            device_loop.set_register(
                "write_count",
                device_loop.register("write_count").saturating_add(1),
            );
            device_loop.set_register("last_command", value);
        }

        if offset == DEVICE_MMIO_QUEUE_CONTROL_OFFSET {
            let role_code = self.device_loops[device_loop_index].register("last_artifact_role");
            let Some(role) = block_control_role_name(role_code) else {
                self.device_loops[device_loop_index].set_register("status_code", 0);
                return SoftVmDeviceMmioEffect {
                    value: 0,
                    detail: format!(
                        "block control rejected block request {value} without an active artifact @ 0x{guest_physical_address:x}"
                    ),
                    interrupt: None,
                };
            };
            return match self.block_control_block_token(role, value) {
                Ok(token) => {
                    let device_loop = &mut self.device_loops[device_loop_index];
                    device_loop.set_register("last_block_index", value);
                    device_loop.set_register("last_transfer_token", token);
                    device_loop.set_register(
                        "block_request_count",
                        device_loop
                            .register("block_request_count")
                            .saturating_add(1),
                    );
                    device_loop.set_register("status_code", 1);
                    let mut responses_ready = 0;
                    if let Some(queue) = device_loop.queue_mut("responses") {
                        queue.pending.push(token);
                        responses_ready = saturating_u64_len(queue.pending.len());
                    }
                    device_loop.set_register("responses_ready", responses_ready);
                    SoftVmDeviceMmioEffect {
                        value: token,
                        detail: format!(
                            "block control queued {role} block {value} token 0x{token:x} @ 0x{guest_physical_address:x}"
                        ),
                        interrupt: Some(SoftVmInjectedInterrupt {
                            vector: interrupt_vector,
                            source: String::from("virt_block_control"),
                            detail: format!(
                                "block control completed {role} block {value} with token 0x{token:x}"
                            ),
                        }),
                    }
                }
                Err(error) => {
                    let device_loop = &mut self.device_loops[device_loop_index];
                    device_loop.set_register("status_code", 0);
                    SoftVmDeviceMmioEffect {
                        value: 0,
                        detail: format!(
                            "block control failed block request {value} for {role}: {}",
                            error.message
                        ),
                        interrupt: None,
                    }
                }
            };
        }

        if offset != 0 {
            return SoftVmDeviceMmioEffect {
                value,
                detail: format!(
                    "block control ignored unsupported write offset 0x{offset:x} @ 0x{guest_physical_address:x}"
                ),
                interrupt: None,
            };
        }

        let pending_stage = self.device_loops[device_loop_index].register("pending_stage");
        if value == u64::from(NATIVE_CALL_BOOT_DEVICE_TRANSFER) {
            let device_loop = &mut self.device_loops[device_loop_index];
            device_loop.set_register("pending_stage", value);
            return SoftVmDeviceMmioEffect {
                value,
                detail: format!(
                    "block control queued boot-device transfer request @ 0x{guest_physical_address:x}"
                ),
                interrupt: None,
            };
        }

        let operation = if pending_stage == u64::from(NATIVE_CALL_BOOT_DEVICE_TRANSFER) {
            match value {
                BLOCK_CONTROL_ROLE_PRIMARY_DISK => {
                    Some(("primary_disk", "boot-device handoff", "transfer_count"))
                }
                BLOCK_CONTROL_ROLE_INSTALL_MEDIA => {
                    Some(("install_media", "boot-device handoff", "transfer_count"))
                }
                _ => None,
            }
        } else if value == BLOCK_CONTROL_COMMAND_PROBE_MEDIA {
            Some(("install_media", "install-media probe", "probe_count"))
        } else {
            None
        };

        let Some((role, operation_name, count_register)) = operation else {
            return SoftVmDeviceMmioEffect {
                value,
                detail: format!(
                    "block control ignored unsupported command 0x{value:x} @ 0x{guest_physical_address:x}"
                ),
                interrupt: None,
            };
        };

        match self.block_control_transfer(role) {
            Ok(transfer) => {
                let device_loop = &mut self.device_loops[device_loop_index];
                device_loop.set_register("pending_stage", 0);
                device_loop.set_register("last_artifact_role", transfer.role_code);
                device_loop.set_register("last_block_index", 0);
                device_loop.set_register("last_transfer_token", transfer.first_block_token);
                device_loop.set_register("last_artifact_bytes", transfer.byte_len);
                device_loop.set_register("last_block_count", transfer.block_count);
                device_loop.set_register(
                    "overlay_attached",
                    if transfer.overlay_attached { 1 } else { 0 },
                );
                device_loop.set_register("read_only", if transfer.read_only { 1 } else { 0 });
                device_loop.set_register(
                    count_register,
                    device_loop.register(count_register).saturating_add(1),
                );
                device_loop.set_register("status_code", 1);
                let mut responses_ready = 0;
                if let Some(queue) = device_loop.queue_mut("responses") {
                    queue.pending.push(transfer.first_block_token);
                    responses_ready = saturating_u64_len(queue.pending.len());
                }
                device_loop.set_register("responses_ready", responses_ready);
                SoftVmDeviceMmioEffect {
                    value: transfer.first_block_token,
                    detail: format!(
                        "block control consumed {} block 0 token 0x{:x} for {} @ 0x{guest_physical_address:x}",
                        transfer.role, transfer.first_block_token, operation_name,
                    ),
                    interrupt: Some(SoftVmInjectedInterrupt {
                        vector: interrupt_vector,
                        source: String::from("virt_block_control"),
                        detail: format!(
                            "block control completed {} for {} with token 0x{:x}",
                            operation_name, transfer.role, transfer.first_block_token,
                        ),
                    }),
                }
            }
            Err(error) => {
                let device_loop = &mut self.device_loops[device_loop_index];
                device_loop.set_register("pending_stage", 0);
                device_loop.set_register("status_code", 0);
                SoftVmDeviceMmioEffect {
                    value: 0,
                    detail: format!(
                        "block control failed {} for {}: {}",
                        operation_name, role, error.message
                    ),
                    interrupt: None,
                }
            }
        }
    }

    fn handle_block_control_mmio_read(
        &mut self,
        device_loop_index: usize,
        guest_physical_address: u64,
    ) -> SoftVmDeviceMmioEffect {
        let offset = self
            .mmio_region_named(self.device_loops[device_loop_index].region_name.as_str())
            .map(|region| guest_physical_address.saturating_sub(region.guest_physical_base))
            .unwrap_or_default();
        if offset == DEVICE_MMIO_STATUS_OFFSET {
            let device_loop = &self.device_loops[device_loop_index];
            let value = packed_u32_pair(
                device_loop.register("responses_ready"),
                device_loop.register("status_code"),
            );
            return SoftVmDeviceMmioEffect {
                value,
                detail: format!(
                    "block control status responses_ready={} status_code={} @ 0x{guest_physical_address:x}",
                    device_loop.register("responses_ready"),
                    device_loop.register("status_code"),
                ),
                interrupt: None,
            };
        }
        if offset == DEVICE_MMIO_QUEUE_CONTROL_OFFSET {
            let device_loop = &self.device_loops[device_loop_index];
            let value = packed_u32_pair(
                device_loop.register("last_block_index"),
                device_loop.register("last_block_count"),
            );
            return SoftVmDeviceMmioEffect {
                value,
                detail: format!(
                    "block control cursor block_index={} total_blocks={} @ 0x{guest_physical_address:x}",
                    device_loop.register("last_block_index"),
                    device_loop.register("last_block_count"),
                ),
                interrupt: None,
            };
        }
        if offset == DEVICE_MMIO_METADATA_OFFSET {
            let value = self.device_loops[device_loop_index].register("last_artifact_bytes");
            return SoftVmDeviceMmioEffect {
                value,
                detail: format!(
                    "block control artifact bytes={value} @ 0x{guest_physical_address:x}"
                ),
                interrupt: None,
            };
        }
        if offset != 0 {
            return SoftVmDeviceMmioEffect {
                value: 0,
                detail: format!(
                    "block control ignored unsupported read offset 0x{offset:x} @ 0x{guest_physical_address:x}"
                ),
                interrupt: None,
            };
        }

        let device_loop = &mut self.device_loops[device_loop_index];
        let status_code = device_loop.register("status_code");
        let mut responses_ready = device_loop.register("responses_ready");
        let value = if let Some(queue) = device_loop.queue_mut("responses") {
            if queue.pending.is_empty() {
                status_code
            } else {
                let drained = queue.pending.remove(0);
                queue.completed.push(drained);
                responses_ready = saturating_u64_len(queue.pending.len());
                drained
            }
        } else {
            status_code
        };
        device_loop.set_register("responses_ready", responses_ready);
        device_loop.set_register(
            "read_count",
            device_loop.register("read_count").saturating_add(1),
        );
        device_loop.set_register("last_read_token", value);
        let role_name =
            block_control_role_name(device_loop.register("last_artifact_role")).unwrap_or("idle");
        let detail = if value == 0 && role_name == "idle" {
            format!("block control reported idle status @ 0x{guest_physical_address:x}")
        } else {
            format!(
                "block control returned token 0x{value:x} from {role_name} @ 0x{guest_physical_address:x}"
            )
        };
        SoftVmDeviceMmioEffect {
            value,
            detail,
            interrupt: None,
        }
    }

    fn dispatch_mmio_write(
        &mut self,
        guest_physical_address: u64,
        value: u64,
        detail_override: Option<String>,
    ) -> Result<String> {
        let region = self
            .mmio_region_for_address(guest_physical_address)?
            .clone();
        let effect = self.handle_device_mmio_write(&region, guest_physical_address, value);
        let detail = detail_override.unwrap_or(effect.detail);
        self.record_mmio_access(
            &region.name,
            "write",
            guest_physical_address,
            value,
            detail.clone(),
        );
        if let Some(interrupt) = effect.interrupt {
            self.queue_interrupt(interrupt.vector, interrupt.source, interrupt.detail);
        }
        Ok(detail)
    }

    fn dispatch_mmio_read(&mut self, guest_physical_address: u64) -> Result<(u64, String)> {
        let region = self
            .mmio_region_for_address(guest_physical_address)?
            .clone();
        let effect = self.handle_device_mmio_read(&region, guest_physical_address);
        self.record_mmio_access(
            &region.name,
            "read",
            guest_physical_address,
            effect.value,
            effect.detail.clone(),
        );
        if let Some(interrupt) = effect.interrupt {
            self.queue_interrupt(interrupt.vector, interrupt.source, interrupt.detail);
        }
        Ok((effect.value, effect.detail))
    }

    fn handle_device_mmio_write(
        &mut self,
        region: &SoftVmMmioRegion,
        guest_physical_address: u64,
        value: u64,
    ) -> SoftVmDeviceMmioEffect {
        let offset = mmio_offset(region, guest_physical_address);
        let default_detail = format!(
            "mmio write {} @ 0x{guest_physical_address:x} = 0x{value:x}",
            region.name
        );
        if offset == DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET {
            let Some(device_loop_index) = self.device_loop_index_by_region(region.name.as_str())
            else {
                return SoftVmDeviceMmioEffect {
                    value,
                    detail: default_detail,
                    interrupt: None,
                };
            };
            return self.handle_device_interrupt_control_write(
                device_loop_index,
                guest_physical_address,
                value,
            );
        }
        if region.name == "virt_block_control" {
            let Some(device_loop_index) = self.device_loop_index_by_region(region.name.as_str())
            else {
                return SoftVmDeviceMmioEffect {
                    value,
                    detail: default_detail,
                    interrupt: None,
                };
            };
            return self.handle_block_control_mmio_write(
                device_loop_index,
                guest_physical_address,
                value,
            );
        }
        let Some(device_loop) = self.device_loop_mut_by_region(region.name.as_str()) else {
            return SoftVmDeviceMmioEffect {
                value,
                detail: default_detail,
                interrupt: None,
            };
        };
        let interrupt_vector = device_loop.interrupt_vector;
        match region.name.as_str() {
            "uart_console" => match offset {
                0 => {
                    let drained = if let Some(queue) = device_loop.queue_mut("tx") {
                        queue.pending.push(value);
                        let drained = queue.pending.remove(0);
                        queue.completed.push(drained);
                        drained
                    } else {
                        value
                    };
                    let byte = u8::try_from(drained & 0xff).unwrap_or(0);
                    device_loop.set_register(
                        "tx_count",
                        device_loop.register("tx_count").saturating_add(1),
                    );
                    device_loop.set_register("last_tx_byte", u64::from(byte));
                    SoftVmDeviceMmioEffect {
                        value: drained,
                        detail: format!(
                            "serial loop drained byte 0x{byte:02x} from uart_console @ 0x{guest_physical_address:x}"
                        ),
                        interrupt: Some(SoftVmInjectedInterrupt {
                            vector: interrupt_vector,
                            source: String::from("uart_console"),
                            detail: format!("serial loop completed transmit byte 0x{byte:02x}"),
                        }),
                    }
                }
                DEVICE_MMIO_QUEUE_CONTROL_OFFSET => {
                    let byte = value & 0xff;
                    let rx_ready = if let Some(queue) = device_loop.queue_mut("rx") {
                        queue.pending.push(byte);
                        saturating_u64_len(queue.pending.len())
                    } else {
                        0
                    };
                    device_loop.set_register("rx_ready", rx_ready);
                    device_loop.set_register(
                        "rx_injections",
                        device_loop.register("rx_injections").saturating_add(1),
                    );
                    device_loop.set_register("last_rx_byte", byte);
                    SoftVmDeviceMmioEffect {
                        value: byte,
                        detail: format!(
                            "serial loop queued inbound byte 0x{byte:02x} @ 0x{guest_physical_address:x}"
                        ),
                        interrupt: Some(SoftVmInjectedInterrupt {
                            vector: interrupt_vector,
                            source: String::from("uart_console"),
                            detail: format!("serial loop received inbound byte 0x{byte:02x}"),
                        }),
                    }
                }
                _ => SoftVmDeviceMmioEffect {
                    value,
                    detail: format!(
                        "uart_console ignored unsupported write offset 0x{offset:x} @ 0x{guest_physical_address:x}"
                    ),
                    interrupt: None,
                },
            },
            "virt_timer" => match offset {
                0 | DEVICE_MMIO_QUEUE_CONTROL_OFFSET => {
                    let fired = if let Some(queue) = device_loop.queue_mut("events") {
                        queue.pending.push(value);
                        let fired = queue.pending.remove(0);
                        queue.completed.push(fired);
                        fired
                    } else {
                        value
                    };
                    let tick_count = device_loop.register("tick_count").saturating_add(1);
                    device_loop.set_register("tick_count", tick_count);
                    device_loop.set_register("last_deadline", fired);
                    if offset == DEVICE_MMIO_QUEUE_CONTROL_OFFSET {
                        device_loop.set_register(
                            "backend_ticks",
                            device_loop.register("backend_ticks").saturating_add(1),
                        );
                    }
                    SoftVmDeviceMmioEffect {
                        value: fired,
                        detail: if offset == 0 {
                            format!(
                                "timer loop armed deadline 0x{fired:x} and completed tick {tick_count}"
                            )
                        } else {
                            format!(
                                "timer loop injected backend deadline 0x{fired:x} and completed tick {tick_count}"
                            )
                        },
                        interrupt: Some(SoftVmInjectedInterrupt {
                            vector: interrupt_vector,
                            source: String::from("virt_timer"),
                            detail: format!("timer loop completed deadline 0x{fired:x}"),
                        }),
                    }
                }
                _ => SoftVmDeviceMmioEffect {
                    value,
                    detail: format!(
                        "virt_timer ignored unsupported write offset 0x{offset:x} @ 0x{guest_physical_address:x}"
                    ),
                    interrupt: None,
                },
            },
            "virtio_console" => match offset {
                0 => {
                    let echoed = if let Some(queue) = device_loop.queue_mut("tx") {
                        queue.pending.push(value);
                        let echoed = queue.pending.remove(0);
                        queue.completed.push(echoed);
                        echoed
                    } else {
                        value
                    };
                    let rx_ready = if let Some(queue) = device_loop.queue_mut("rx") {
                        queue.pending.push(echoed);
                        saturating_u64_len(queue.pending.len())
                    } else {
                        0
                    };
                    device_loop.set_register("rx_ready", rx_ready);
                    device_loop.set_register(
                        "tx_messages",
                        device_loop.register("tx_messages").saturating_add(1),
                    );
                    device_loop.set_register("last_console_token", echoed);
                    SoftVmDeviceMmioEffect {
                        value: echoed,
                        detail: format!(
                            "virtio console loop echoed token 0x{echoed:x} through queue @ 0x{guest_physical_address:x}"
                        ),
                        interrupt: Some(SoftVmInjectedInterrupt {
                            vector: interrupt_vector,
                            source: String::from("virtio_console"),
                            detail: format!("virtio console loop completed token 0x{echoed:x}"),
                        }),
                    }
                }
                DEVICE_MMIO_QUEUE_CONTROL_OFFSET => {
                    let rx_ready = if let Some(queue) = device_loop.queue_mut("rx") {
                        queue.pending.push(value);
                        saturating_u64_len(queue.pending.len())
                    } else {
                        0
                    };
                    device_loop.set_register("rx_ready", rx_ready);
                    device_loop.set_register(
                        "rx_injections",
                        device_loop.register("rx_injections").saturating_add(1),
                    );
                    device_loop.set_register("last_rx_token", value);
                    SoftVmDeviceMmioEffect {
                        value,
                        detail: format!(
                            "virtio console loop queued inbound token 0x{value:x} @ 0x{guest_physical_address:x}"
                        ),
                        interrupt: Some(SoftVmInjectedInterrupt {
                            vector: interrupt_vector,
                            source: String::from("virtio_console"),
                            detail: format!(
                                "virtio console loop received inbound token 0x{value:x}"
                            ),
                        }),
                    }
                }
                _ => SoftVmDeviceMmioEffect {
                    value,
                    detail: format!(
                        "virtio_console ignored unsupported write offset 0x{offset:x} @ 0x{guest_physical_address:x}"
                    ),
                    interrupt: None,
                },
            },
            "virtio_rng" => {
                let seed = value ^ 0xa5a5_5a5a_d3c4_b2a1;
                device_loop.set_register("seed", seed);
                SoftVmDeviceMmioEffect {
                    value,
                    detail: format!("virtio rng control updated deterministic seed to 0x{seed:x}"),
                    interrupt: None,
                }
            }
            "virtio_net" => match offset {
                0 => {
                    let loopback = if let Some(queue) = device_loop.queue_mut("tx") {
                        queue.pending.push(value);
                        let loopback = queue.pending.remove(0);
                        queue.completed.push(loopback);
                        loopback
                    } else {
                        value
                    };
                    let rx_ready = if let Some(queue) = device_loop.queue_mut("rx") {
                        queue.pending.push(loopback);
                        saturating_u64_len(queue.pending.len())
                    } else {
                        0
                    };
                    device_loop.set_register("rx_ready", rx_ready);
                    device_loop.set_register(
                        "tx_packets",
                        device_loop.register("tx_packets").saturating_add(1),
                    );
                    device_loop.set_register("last_packet_token", loopback);
                    SoftVmDeviceMmioEffect {
                        value: loopback,
                        detail: format!(
                            "virtio net loop transferred packet token 0x{loopback:x} into rx queue"
                        ),
                        interrupt: Some(SoftVmInjectedInterrupt {
                            vector: interrupt_vector,
                            source: String::from("virtio_net"),
                            detail: format!(
                                "virtio net loop completed packet token 0x{loopback:x}"
                            ),
                        }),
                    }
                }
                DEVICE_MMIO_QUEUE_CONTROL_OFFSET => {
                    let rx_ready = if let Some(queue) = device_loop.queue_mut("rx") {
                        queue.pending.push(value);
                        saturating_u64_len(queue.pending.len())
                    } else {
                        0
                    };
                    device_loop.set_register("rx_ready", rx_ready);
                    device_loop.set_register(
                        "injected_packets",
                        device_loop.register("injected_packets").saturating_add(1),
                    );
                    device_loop.set_register("last_rx_token", value);
                    SoftVmDeviceMmioEffect {
                        value,
                        detail: format!(
                            "virtio net loop queued inbound packet token 0x{value:x} @ 0x{guest_physical_address:x}"
                        ),
                        interrupt: Some(SoftVmInjectedInterrupt {
                            vector: interrupt_vector,
                            source: String::from("virtio_net"),
                            detail: format!(
                                "virtio net loop received inbound packet token 0x{value:x}"
                            ),
                        }),
                    }
                }
                _ => SoftVmDeviceMmioEffect {
                    value,
                    detail: format!(
                        "virtio_net ignored unsupported write offset 0x{offset:x} @ 0x{guest_physical_address:x}"
                    ),
                    interrupt: None,
                },
            },
            _ => SoftVmDeviceMmioEffect {
                value,
                detail: default_detail,
                interrupt: None,
            },
        }
    }

    fn handle_device_mmio_read(
        &mut self,
        region: &SoftVmMmioRegion,
        guest_physical_address: u64,
    ) -> SoftVmDeviceMmioEffect {
        let offset = mmio_offset(region, guest_physical_address);
        let default_detail = format!(
            "mmio read {} @ 0x{guest_physical_address:x}",
            region.name.as_str()
        );
        if offset == DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET {
            let Some(device_loop_index) = self.device_loop_index_by_region(region.name.as_str())
            else {
                return SoftVmDeviceMmioEffect {
                    value: 0,
                    detail: format!("{default_detail} -> 0x0"),
                    interrupt: None,
                };
            };
            return self
                .handle_device_interrupt_control_read(device_loop_index, guest_physical_address);
        }
        if region.name == "virt_block_control" {
            let Some(device_loop_index) = self.device_loop_index_by_region(region.name.as_str())
            else {
                return SoftVmDeviceMmioEffect {
                    value: 0,
                    detail: format!("{default_detail} -> 0x0"),
                    interrupt: None,
                };
            };
            return self.handle_block_control_mmio_read(device_loop_index, guest_physical_address);
        }
        let pending_interrupt_count = self.pending_interrupt_count_for_source(region.name.as_str());
        let Some(device_loop) = self.device_loop_mut_by_region(region.name.as_str()) else {
            return SoftVmDeviceMmioEffect {
                value: 0,
                detail: format!("{default_detail} -> 0x0"),
                interrupt: None,
            };
        };
        let interrupt_vector = device_loop.interrupt_vector;
        match region.name.as_str() {
            "uart_console" => match offset {
                0 => {
                    let value = if let Some(queue) = device_loop.queue_mut("rx") {
                        if queue.pending.is_empty() {
                            0
                        } else {
                            let value = queue.pending.remove(0);
                            queue.completed.push(value);
                            value
                        }
                    } else {
                        0
                    };
                    device_loop.set_register("rx_ready", device_loop.queue_pending_len("rx"));
                    if value != 0 {
                        device_loop.set_register(
                            "rx_count",
                            device_loop.register("rx_count").saturating_add(1),
                        );
                        device_loop.set_register("last_rx_byte", value & 0xff);
                    }
                    SoftVmDeviceMmioEffect {
                        value,
                        detail: format!(
                            "serial loop sampled byte 0x{:02x} from uart_console",
                            value & 0xff
                        ),
                        interrupt: None,
                    }
                }
                DEVICE_MMIO_STATUS_OFFSET => {
                    let value = packed_u32_pair(
                        device_loop.queue_pending_len("rx"),
                        device_loop.queue_completed_len("tx"),
                    );
                    SoftVmDeviceMmioEffect {
                        value,
                        detail: format!(
                            "uart_console status rx_pending={} tx_completed={} @ 0x{guest_physical_address:x}",
                            device_loop.queue_pending_len("rx"),
                            device_loop.queue_completed_len("tx"),
                        ),
                        interrupt: None,
                    }
                }
                DEVICE_MMIO_QUEUE_CONTROL_OFFSET => {
                    let value = packed_u32_pair(
                        device_loop.register("last_rx_byte"),
                        device_loop.register("last_tx_byte"),
                    );
                    SoftVmDeviceMmioEffect {
                        value,
                        detail: format!(
                            "uart_console last bytes rx=0x{:02x} tx=0x{:02x} @ 0x{guest_physical_address:x}",
                            device_loop.register("last_rx_byte"),
                            device_loop.register("last_tx_byte"),
                        ),
                        interrupt: None,
                    }
                }
                DEVICE_MMIO_METADATA_OFFSET => {
                    let value = packed_u32_pair(
                        device_loop.register("rx_count"),
                        device_loop.register("tx_count"),
                    );
                    SoftVmDeviceMmioEffect {
                        value,
                        detail: format!(
                            "uart_console counters rx={} tx={} @ 0x{guest_physical_address:x}",
                            device_loop.register("rx_count"),
                            device_loop.register("tx_count"),
                        ),
                        interrupt: None,
                    }
                }
                _ => SoftVmDeviceMmioEffect {
                    value: 0,
                    detail: format!(
                        "uart_console ignored unsupported read offset 0x{offset:x} @ 0x{guest_physical_address:x}"
                    ),
                    interrupt: None,
                },
            },
            "virt_timer" => match offset {
                0 => {
                    let tick_count = device_loop.register("tick_count");
                    SoftVmDeviceMmioEffect {
                        value: tick_count,
                        detail: format!("timer loop reported tick_count={tick_count}"),
                        interrupt: None,
                    }
                }
                DEVICE_MMIO_STATUS_OFFSET => {
                    let value = packed_u32_pair(
                        device_loop.queue_completed_len("events"),
                        pending_interrupt_count,
                    );
                    SoftVmDeviceMmioEffect {
                        value,
                        detail: format!(
                            "virt_timer status completed_events={} pending_interrupts={} @ 0x{guest_physical_address:x}",
                            device_loop.queue_completed_len("events"),
                            pending_interrupt_count,
                        ),
                        interrupt: None,
                    }
                }
                DEVICE_MMIO_QUEUE_CONTROL_OFFSET => SoftVmDeviceMmioEffect {
                    value: device_loop.register("last_deadline"),
                    detail: format!(
                        "virt_timer last_deadline=0x{:x} @ 0x{guest_physical_address:x}",
                        device_loop.register("last_deadline"),
                    ),
                    interrupt: None,
                },
                DEVICE_MMIO_METADATA_OFFSET => SoftVmDeviceMmioEffect {
                    value: device_loop.register("tick_count"),
                    detail: format!(
                        "virt_timer metadata tick_count={} @ 0x{guest_physical_address:x}",
                        device_loop.register("tick_count"),
                    ),
                    interrupt: None,
                },
                _ => SoftVmDeviceMmioEffect {
                    value: 0,
                    detail: format!(
                        "virt_timer ignored unsupported read offset 0x{offset:x} @ 0x{guest_physical_address:x}"
                    ),
                    interrupt: None,
                },
            },
            "virtio_console" => match offset {
                0 => {
                    let value = if let Some(queue) = device_loop.queue_mut("rx") {
                        if queue.pending.is_empty() {
                            0
                        } else {
                            let value = queue.pending.remove(0);
                            queue.completed.push(value);
                            value
                        }
                    } else {
                        0
                    };
                    let rx_ready = device_loop.queue_pending_len("rx");
                    device_loop.set_register("rx_ready", rx_ready);
                    if value != 0 {
                        device_loop.set_register(
                            "rx_messages",
                            device_loop.register("rx_messages").saturating_add(1),
                        );
                        device_loop.set_register("last_rx_token", value);
                    }
                    SoftVmDeviceMmioEffect {
                        value,
                        detail: format!("virtio console loop received token 0x{value:x}"),
                        interrupt: None,
                    }
                }
                DEVICE_MMIO_STATUS_OFFSET => {
                    let value = packed_u32_pair(
                        device_loop.queue_pending_len("rx"),
                        device_loop.queue_completed_len("tx"),
                    );
                    SoftVmDeviceMmioEffect {
                        value,
                        detail: format!(
                            "virtio_console status rx_pending={} tx_completed={} @ 0x{guest_physical_address:x}",
                            device_loop.queue_pending_len("rx"),
                            device_loop.queue_completed_len("tx"),
                        ),
                        interrupt: None,
                    }
                }
                DEVICE_MMIO_QUEUE_CONTROL_OFFSET => {
                    let value = packed_u32_pair(
                        device_loop.register("last_rx_token"),
                        device_loop.register("last_console_token"),
                    );
                    SoftVmDeviceMmioEffect {
                        value,
                        detail: format!(
                            "virtio_console last tokens rx=0x{:x} tx=0x{:x} @ 0x{guest_physical_address:x}",
                            device_loop.register("last_rx_token"),
                            device_loop.register("last_console_token"),
                        ),
                        interrupt: None,
                    }
                }
                DEVICE_MMIO_METADATA_OFFSET => {
                    let value = packed_u32_pair(
                        device_loop.register("rx_messages"),
                        device_loop.register("tx_messages"),
                    );
                    SoftVmDeviceMmioEffect {
                        value,
                        detail: format!(
                            "virtio_console counters rx={} tx={} @ 0x{guest_physical_address:x}",
                            device_loop.register("rx_messages"),
                            device_loop.register("tx_messages"),
                        ),
                        interrupt: None,
                    }
                }
                _ => SoftVmDeviceMmioEffect {
                    value: 0,
                    detail: format!(
                        "virtio_console ignored unsupported read offset 0x{offset:x} @ 0x{guest_physical_address:x}"
                    ),
                    interrupt: None,
                },
            },
            "virtio_rng" => {
                let seed = device_loop
                    .register("seed")
                    .wrapping_add(0x9e37_79b9_7f4a_7c15);
                let entropy = splitmix64(seed);
                device_loop.set_register("seed", seed);
                device_loop.set_register(
                    "requests",
                    device_loop.register("requests").saturating_add(1),
                );
                device_loop.set_register("last_entropy", entropy);
                if let Some(queue) = device_loop.queue_mut("entropy") {
                    queue.pending.push(entropy);
                    let drained = queue.pending.remove(0);
                    queue.completed.push(drained);
                }
                SoftVmDeviceMmioEffect {
                    value: entropy,
                    detail: format!("virtio rng loop produced entropy word 0x{entropy:x}"),
                    interrupt: Some(SoftVmInjectedInterrupt {
                        vector: interrupt_vector,
                        source: String::from("virtio_rng"),
                        detail: format!("virtio rng loop produced entropy word 0x{entropy:x}"),
                    }),
                }
            }
            "virtio_net" => match offset {
                0 => {
                    let value = if let Some(queue) = device_loop.queue_mut("rx") {
                        if queue.pending.is_empty() {
                            0
                        } else {
                            let value = queue.pending.remove(0);
                            queue.completed.push(value);
                            value
                        }
                    } else {
                        0
                    };
                    let rx_ready = device_loop.queue_pending_len("rx");
                    device_loop.set_register("rx_ready", rx_ready);
                    if value != 0 {
                        device_loop.set_register(
                            "rx_packets",
                            device_loop.register("rx_packets").saturating_add(1),
                        );
                        device_loop.set_register("last_rx_token", value);
                    }
                    SoftVmDeviceMmioEffect {
                        value,
                        detail: format!("virtio net loop received packet token 0x{value:x}"),
                        interrupt: None,
                    }
                }
                DEVICE_MMIO_STATUS_OFFSET => {
                    let value = packed_u32_pair(
                        device_loop.queue_pending_len("rx"),
                        device_loop.queue_completed_len("tx"),
                    );
                    SoftVmDeviceMmioEffect {
                        value,
                        detail: format!(
                            "virtio_net status rx_pending={} tx_completed={} @ 0x{guest_physical_address:x}",
                            device_loop.queue_pending_len("rx"),
                            device_loop.queue_completed_len("tx"),
                        ),
                        interrupt: None,
                    }
                }
                DEVICE_MMIO_QUEUE_CONTROL_OFFSET => {
                    let value = packed_u32_pair(
                        device_loop.register("last_rx_token"),
                        device_loop.register("last_packet_token"),
                    );
                    SoftVmDeviceMmioEffect {
                        value,
                        detail: format!(
                            "virtio_net last tokens rx=0x{:x} tx=0x{:x} @ 0x{guest_physical_address:x}",
                            device_loop.register("last_rx_token"),
                            device_loop.register("last_packet_token"),
                        ),
                        interrupt: None,
                    }
                }
                DEVICE_MMIO_METADATA_OFFSET => {
                    let value = packed_u32_pair(
                        device_loop.register("rx_packets"),
                        device_loop.register("tx_packets"),
                    );
                    SoftVmDeviceMmioEffect {
                        value,
                        detail: format!(
                            "virtio_net counters rx={} tx={} @ 0x{guest_physical_address:x}",
                            device_loop.register("rx_packets"),
                            device_loop.register("tx_packets"),
                        ),
                        interrupt: None,
                    }
                }
                _ => SoftVmDeviceMmioEffect {
                    value: 0,
                    detail: format!(
                        "virtio_net ignored unsupported read offset 0x{offset:x} @ 0x{guest_physical_address:x}"
                    ),
                    interrupt: None,
                },
            },
            _ => SoftVmDeviceMmioEffect {
                value: 0,
                detail: format!("{default_detail} -> 0x0"),
                interrupt: None,
            },
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn read_instruction_byte(&mut self) -> Result<u8> {
        let guest_address = self.cpu_state.instruction_pointer;
        if let Some(page) = self.guest_memory_bytes.page(guest_address)
            && (!page.permissions.readable || !page.permissions.executable)
        {
            return self.raise_fault(
                0x0e,
                format!(
                    "guest instruction fetch at 0x{guest_address:x} violates execute permission"
                ),
            );
        }
        let value = if let Some(value) = self.guest_memory_bytes.get(&guest_address).copied() {
            value
        } else {
            return self.raise_fault(
                0x06,
                format!("guest ISA ended before byte at 0x{guest_address:x} could be read"),
            );
        };
        self.cpu_state.instruction_pointer = self.cpu_state.instruction_pointer.saturating_add(1);
        Ok(value)
    }

    fn push_guest_stack_u64(&mut self, value: u64) -> Result<()> {
        self.cpu_state.stack_pointer = self
            .cpu_state
            .stack_pointer
            .checked_sub(8)
            .ok_or_else(|| PlatformError::conflict("guest stack pointer underflowed"))?;
        for (offset, byte) in value.to_le_bytes().iter().enumerate() {
            let guest_offset = u64::try_from(offset).map_err(|_| {
                PlatformError::invalid("guest stack write offset exceeds u64 addressability")
            })?;
            self.write_guest_runtime_byte(
                self.cpu_state.stack_pointer.saturating_add(guest_offset),
                *byte,
            )?;
        }
        self.cpu_state.call_depth = self.cpu_state.call_depth.saturating_add(1);
        Ok(())
    }

    fn pop_guest_stack_u64(&mut self) -> Result<u64> {
        if self.cpu_state.call_depth == 0 {
            return self.raise_fault(
                0x0d,
                "guest return attempted with an empty synthetic call stack",
            );
        }
        let bytes = self.guest_memory_slice(self.cpu_state.stack_pointer, 8);
        let byte_array: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
            PlatformError::invalid("guest stack return slot did not contain eight bytes")
        })?;
        let value = u64::from_le_bytes(byte_array);
        for offset in 0..8u64 {
            let address = self.cpu_state.stack_pointer.saturating_add(offset);
            self.clear_guest_runtime_byte(address)?;
        }
        self.cpu_state.stack_pointer = self.cpu_state.stack_pointer.saturating_add(8);
        self.cpu_state.call_depth = self.cpu_state.call_depth.saturating_sub(1);
        Ok(value)
    }

    fn advance_guest_instruction(&mut self, outcome: &mut SoftVmProgramOutcome) {
        self.steps_executed = self.steps_executed.saturating_add(1);
        outcome.instruction_count = outcome.instruction_count.saturating_add(1);
    }

    fn interrupt_vector_for_source(&self, source: &str, fallback: u8) -> u8 {
        self.machine_topology
            .interrupt_for_source(source)
            .map_or(fallback, |interrupt| interrupt.vector)
    }

    fn mmio_region_for_interrupt_source(&self, source: &str) -> Option<&SoftVmMmioRegion> {
        let device_name = self
            .machine_topology
            .devices
            .iter()
            .find(|device| device.irq_source.as_deref() == Some(source))
            .map(|device| device.name.as_str())?;
        self.mmio_regions
            .iter()
            .find(|region| region.name == device_name)
    }

    fn record_timer_signal(&mut self, value: u64) {
        if let Some(device_loop) = self.device_loop_mut_by_name("virt_timer") {
            let fired = if let Some(queue) = device_loop.queue_mut("events") {
                queue.pending.push(value);
                let fired = queue.pending.remove(0);
                queue.completed.push(fired);
                fired
            } else {
                value
            };
            device_loop.set_register(
                "tick_count",
                device_loop.register("tick_count").saturating_add(1),
            );
            device_loop.set_register("last_deadline", fired);
        }
    }

    fn queue_interrupt(
        &mut self,
        vector: u8,
        source: impl Into<String>,
        detail: impl Into<String>,
    ) {
        let source = source.into();
        let detail = detail.into();
        let vector = self.interrupt_vector_for_source(source.as_str(), vector);
        let is_edge_triggered =
            self.interrupt_trigger_for_source(source.as_str()) == Some("edge_rising");
        let device_loop_index = self.device_loop_index_by_name(source.as_str());
        if let Some(device_loop_index) = device_loop_index {
            let masked = self.device_loops[device_loop_index].register("interrupt_masked") != 0;
            self.device_loops[device_loop_index]
                .set_register("last_interrupt_vector", u64::from(vector));
            if masked {
                let pending_count = self.pending_interrupt_count_for_source(source.as_str());
                let device_loop = &mut self.device_loops[device_loop_index];
                device_loop.set_register("interrupt_latched", 1);
                device_loop.set_register(
                    "latched_interrupt_count",
                    device_loop
                        .register("latched_interrupt_count")
                        .saturating_add(1),
                );
                device_loop.set_register("interrupt_pending", pending_count);
                return;
            }
            self.device_loops[device_loop_index].set_register("interrupt_latched", 0);
        }
        self.cpu_state.last_trap_vector = Some(vector);
        self.cpu_state.last_trap_detail = Some(detail.clone());
        if !is_edge_triggered {
            self.pending_interrupts
                .retain(|interrupt| interrupt.vector != vector || interrupt.source != source);
        }
        if let Some(device_loop_index) = device_loop_index {
            let device_loop = &mut self.device_loops[device_loop_index];
            device_loop.set_register(
                "interrupt_count",
                device_loop.register("interrupt_count").saturating_add(1),
            );
        }
        if let Some((region_name, guest_physical_base)) = self
            .mmio_region_for_interrupt_source(source.as_str())
            .map(|region| (region.name.clone(), region.guest_physical_base))
        {
            self.record_mmio_access(
                &region_name,
                "write",
                guest_physical_base,
                u64::from(vector),
                detail.clone(),
            );
        }
        self.pending_interrupts.push(SoftVmPendingInterrupt {
            vector,
            source: source.clone(),
            detail,
        });
        if let Some(device_loop_index) = device_loop_index {
            let pending_count = self.pending_interrupt_count_for_source(source.as_str());
            self.device_loops[device_loop_index].set_register("interrupt_pending", pending_count);
        }
    }

    fn record_mmio_access(
        &mut self,
        region_name: &str,
        access_kind: &str,
        guest_physical_address: u64,
        value: u64,
        detail: impl Into<String>,
    ) {
        self.mmio_access_log.push(SoftVmMmioAccess {
            region_name: String::from(region_name),
            access_kind: String::from(access_kind),
            guest_physical_address,
            value,
            detail: detail.into(),
        });
        if self.mmio_access_log.len() > 64 {
            let overflow = self.mmio_access_log.len().saturating_sub(64);
            self.mmio_access_log.drain(0..overflow);
        }
    }

    fn raise_fault<T>(&mut self, vector: u8, detail: impl Into<String>) -> Result<T> {
        let detail = detail.into();
        self.cpu_state.faulted = true;
        self.cpu_state.fault_vector = Some(vector);
        self.cpu_state.fault_detail = Some(detail.clone());
        self.cpu_state.trap_frame_depth = self.cpu_state.trap_frame_depth.saturating_add(1);
        self.queue_interrupt(vector, "cpu_fault", detail.clone());
        Err(PlatformError::invalid(detail))
    }

    fn refresh_guest_program_outcome(
        &mut self,
        control: &SoftVmGuestControl,
        outcome: &mut SoftVmProgramOutcome,
    ) -> Result<()> {
        let kernel_result_ready = read_guest_file(self, control, "/run/guest-kernel/operation")
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);
        if !kernel_result_ready {
            self.cpu_state.zero_flag = outcome.exit_code == 0;
            self.cpu_state.sign_flag = outcome.exit_code < 0;
            self.cpu_state.carry_flag = outcome.exit_code > 0;
            return Ok(());
        }
        outcome.stdout =
            read_guest_file(self, control, "/run/guest-kernel/stdout").ok_or_else(|| {
                PlatformError::unavailable("missing guest-kernel stdout file after operation")
            })?;
        outcome.stderr =
            read_guest_file(self, control, "/run/guest-kernel/stderr").ok_or_else(|| {
                PlatformError::unavailable("missing guest-kernel stderr file after operation")
            })?;
        outcome.exit_code = read_guest_file(self, control, "/run/guest-kernel/exit-code")
            .ok_or_else(|| {
                PlatformError::unavailable("missing guest-kernel exit-code file after operation")
            })?
            .trim()
            .parse::<i32>()
            .map_err(|error| {
                PlatformError::invalid("invalid guest-kernel exit-code file after operation")
                    .with_detail(error.to_string())
            })?;
        self.cpu_state.zero_flag = outcome.exit_code == 0;
        self.cpu_state.sign_flag = outcome.exit_code < 0;
        self.cpu_state.carry_flag = outcome.exit_code > 0;
        Ok(())
    }

    fn record_trace(
        &mut self,
        program: &SoftVmResidentProgram,
        guest_address: u64,
        opcode: u8,
        detail: String,
    ) {
        self.record_trace_for_program_name(program.name.as_str(), guest_address, opcode, detail);
    }

    fn record_trace_for_program_name(
        &mut self,
        program_name: &str,
        guest_address: u64,
        opcode: u8,
        detail: String,
    ) {
        self.instruction_trace.push(SoftVmInstructionTrace {
            program_name: String::from(program_name),
            guest_address,
            opcode: String::from(opcode_name(opcode)),
            detail,
        });
    }

    fn enter_direct_kernel(&mut self) -> Result<BootServiceStageCompletion> {
        let state = self.direct_kernel_state()?.clone();
        self.write_register(ISA_REGISTER_ARG0, state.kernel_entry_guest_address)?;
        self.write_register(ISA_REGISTER_ARG1, state.boot_params_guest_address)?;
        self.write_register(ISA_REGISTER_ARG2, state.command_line_guest_address)?;
        self.write_register(ISA_REGISTER_ARG3, state.kernel_byte_len)?;
        let detail = format!(
            "direct kernel {} handoff prepared at 0x{:x} ({} bytes, preview {} bytes) with boot params 0x{:x} and cmdline 0x{:x}",
            boot_artifact_display_name(&state.kernel_source),
            state.kernel_entry_guest_address,
            state.kernel_byte_len,
            state.preview_byte_len,
            state.boot_params_guest_address,
            state.command_line_guest_address,
        );
        Ok(BootServiceStageCompletion {
            event_kind: "direct_kernel_entry",
            detail: detail.clone(),
            stage_marker: String::from("direct_kernel:entry_complete"),
            console_line: format!(
                "Direct kernel handoff prepared entry=0x{:x} boot_params=0x{:x} cmdline=0x{:x}",
                state.kernel_entry_guest_address,
                state.boot_params_guest_address,
                state.command_line_guest_address,
            ),
            guest_control_ready: false,
            mmio_access: None,
        })
    }

    fn write_register(&mut self, register: u8, value: u64) -> Result<()> {
        let slot = self
            .cpu_state
            .general_purpose_registers
            .get_mut(usize::from(register))
            .ok_or_else(|| PlatformError::invalid("guest ISA register index is out of range"))?;
        *slot = value;
        Ok(())
    }

    fn read_register(&self, register: u8) -> Result<u64> {
        self.cpu_state
            .general_purpose_registers
            .get(usize::from(register))
            .copied()
            .ok_or_else(|| PlatformError::invalid("guest ISA register index is out of range"))
    }

    fn read_guest_string_from_span(&self, guest_address: u64, byte_len: u64) -> Result<String> {
        String::from_utf8(self.guest_memory_slice(guest_address, byte_len)).map_err(|error| {
            PlatformError::invalid("guest memory span is not valid utf-8")
                .with_detail(error.to_string())
        })
    }
}

fn maybe_local_boot_artifact_path(value: &str) -> Option<PathBuf> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(path) = trimmed.strip_prefix("file://") {
        let path = PathBuf::from(path);
        return path.is_absolute().then_some(path);
    }
    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        return Some(path);
    }
    None
}

fn resolve_known_firmware_artifact_path(source: &str) -> Result<Option<PathBuf>> {
    let normalized = source.trim().to_ascii_lowercase();
    let (candidates, staged_name) = match normalized.as_str() {
        "bios" => (
            &[
                "/usr/share/seabios/bios.bin",
                "/usr/share/seabios/bios-256k.bin",
            ][..],
            "bios.bin",
        ),
        "uefi_standard" => (
            &[
                "/usr/share/OVMF/OVMF_CODE.fd",
                "/usr/share/OVMF/OVMF_CODE_4M.fd",
            ][..],
            "uefi_standard.fd",
        ),
        "uefi_secure" => (
            &[
                "/usr/share/OVMF/OVMF_CODE.secboot.fd",
                "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
            ][..],
            "uefi_secure.fd",
        ),
        _ => return Ok(None),
    };

    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Ok(Some(path));
        }
    }

    let staged_root = std::env::temp_dir().join("uhost-softvm-firmware-artifacts");
    fs::create_dir_all(&staged_root).map_err(|error| {
        PlatformError::unavailable("failed to stage software-backed firmware artifact")
            .with_detail(error.to_string())
    })?;
    let staged_path = staged_root.join(staged_name);
    if !staged_path.exists() {
        let contents = format!("uhost-softvm-firmware-profile:{normalized}\n");
        fs::write(&staged_path, contents.as_bytes()).map_err(|error| {
            PlatformError::unavailable("failed to write staged software-backed firmware artifact")
                .with_detail(error.to_string())
        })?;
    }
    Ok(Some(staged_path))
}

fn resolve_local_boot_artifact_path(role: &str, source: &str) -> Result<Option<PathBuf>> {
    if let Some(path) = maybe_local_boot_artifact_path(source) {
        return Ok(Some(path));
    }
    if role == "firmware" {
        return resolve_known_firmware_artifact_path(source);
    }
    Ok(None)
}

fn ensure_local_execution_artifact(role: &str, source: &str) -> Result<()> {
    if resolve_local_boot_artifact_path(role, source)?.is_none() {
        return Err(PlatformError::conflict(format!(
            "software-backed VM execution requires a local absolute path or file:// URI for {role} artifact"
        ))
        .with_detail(source.to_owned()));
    }
    Ok(())
}

fn load_boot_artifact_preview_with_policy(
    role: &str,
    source: &str,
    artifact_policy: SoftVmArtifactPolicy,
) -> Result<SoftVmLoadedArtifactPreview> {
    let local_path = resolve_local_boot_artifact_path(role, source)?;
    if artifact_policy.requires_local_files() && local_path.is_none() {
        return Err(PlatformError::conflict(format!(
            "software-backed VM execution requires a local absolute path or file:// URI for {role} artifact"
        ))
        .with_detail(source.to_owned()));
    }
    let (byte_len, preview) = if let Some(path) = local_path.as_ref() {
        let bytes = fs::read(path).map_err(|error| {
            PlatformError::unavailable(format!("failed to load {role} artifact"))
                .with_detail(error.to_string())
        })?;
        let byte_len = u64::try_from(bytes.len())
            .map_err(|_| PlatformError::invalid(format!("{role} artifact exceeds u64 size")))?;
        (
            byte_len,
            bytes
                .into_iter()
                .take(MAX_BOOT_ARTIFACT_PREVIEW_BYTES)
                .collect::<Vec<_>>(),
        )
    } else {
        let preview = source
            .as_bytes()
            .iter()
            .copied()
            .cycle()
            .take(source.len().clamp(16, 256))
            .collect::<Vec<_>>();
        (u64::try_from(preview.len()).unwrap_or(u64::MAX), preview)
    };
    Ok(SoftVmLoadedArtifactPreview {
        local_path,
        byte_len,
        preview,
    })
}

fn load_boot_artifact_with_policy(
    role: &str,
    source: &str,
    mapped_region: &str,
    artifact_policy: SoftVmArtifactPolicy,
) -> Result<SoftVmBootArtifact> {
    let loaded_artifact = load_boot_artifact_preview_with_policy(role, source, artifact_policy)?;
    Ok(SoftVmBootArtifact {
        role: String::from(role),
        source: String::from(source),
        byte_len: loaded_artifact.byte_len,
        preview_loaded_bytes: loaded_artifact.preview.len(),
        mapped_region: String::from(mapped_region),
        content_fingerprint: sha256_hex(&loaded_artifact.preview),
        delivery_model: String::from("memory_mapped_preview"),
        resolved_local_path: loaded_artifact
            .local_path
            .map(|path| path.to_string_lossy().into_owned()),
        block_size_bytes: None,
        block_count: None,
        read_only: true,
        overlay: None,
    })
}

fn load_block_boot_artifact_with_policy(
    role: &str,
    source: &str,
    artifact_policy: SoftVmArtifactPolicy,
    read_only: bool,
) -> Result<SoftVmBootArtifact> {
    let local_path = resolve_local_boot_artifact_path(role, source)?;
    if artifact_policy.requires_local_files() && local_path.is_none() {
        return Err(PlatformError::conflict(format!(
            "software-backed VM execution requires a local absolute path or file:// URI for {role} artifact"
        ))
        .with_detail(source.to_owned()));
    }
    let (byte_len, content_fingerprint) = if let Some(path) = local_path.as_ref() {
        let bytes = fs::read(path).map_err(|error| {
            PlatformError::unavailable(format!("failed to load {role} block artifact"))
                .with_detail(error.to_string())
        })?;
        let byte_len = u64::try_from(bytes.len())
            .map_err(|_| PlatformError::invalid(format!("{role} artifact exceeds u64 size")))?;
        if byte_len == 0 {
            return Err(PlatformError::invalid(format!(
                "{role} block artifact may not be empty"
            )));
        }
        (byte_len, sha256_hex(&bytes))
    } else {
        let source_bytes = source.as_bytes();
        let seed_len = u64::try_from(source_bytes.len()).map_err(|_| {
            PlatformError::invalid(format!("{role} source token exceeds u64 addressability"))
        })?;
        let byte_len = seed_len.max(u64::from(DEFAULT_BLOCK_SIZE_BYTES));
        (byte_len, sha256_hex(source_bytes))
    };
    let block_count = block_count_for_bytes(byte_len, DEFAULT_BLOCK_SIZE_BYTES);
    let overlay = (!read_only).then(|| {
        SoftVmWritableOverlay::new(format!("{role}_overlay"), content_fingerprint.clone())
    });
    Ok(SoftVmBootArtifact {
        role: String::from(role),
        source: String::from(source),
        byte_len,
        preview_loaded_bytes: 0,
        mapped_region: String::from("virt_block_control"),
        content_fingerprint,
        delivery_model: String::from("block_device"),
        resolved_local_path: local_path.map(|path| path.to_string_lossy().into_owned()),
        block_size_bytes: Some(DEFAULT_BLOCK_SIZE_BYTES),
        block_count: Some(block_count),
        read_only,
        overlay,
    })
}

fn block_count_for_bytes(byte_len: u64, block_size_bytes: u32) -> u64 {
    let block_size = u64::from(block_size_bytes);
    byte_len
        .saturating_add(block_size.saturating_sub(1))
        .saturating_div(block_size)
}

fn validate_block_artifact_range(
    role: &str,
    artifact: &SoftVmBootArtifact,
    offset: u64,
    byte_len: usize,
) -> Result<()> {
    if !artifact.is_block_device() {
        return Err(PlatformError::conflict(format!(
            "{role} is not exposed through the block substrate"
        )));
    }
    let byte_len_u64 = u64::try_from(byte_len)
        .map_err(|_| PlatformError::invalid(format!("{role} range exceeds u64 addressability")))?;
    let end = offset
        .checked_add(byte_len_u64)
        .ok_or_else(|| PlatformError::invalid(format!("{role} range overflows address space")))?;
    if end > artifact.byte_len {
        return Err(PlatformError::conflict(format!(
            "{role} range exceeds block artifact length"
        )));
    }
    if artifact.block_size_bytes.is_none() || artifact.block_count.is_none() {
        return Err(PlatformError::conflict(format!(
            "{role} block artifact is missing geometry"
        )));
    }
    Ok(())
}

fn read_block_artifact_range(
    role: &str,
    artifact: &SoftVmBootArtifact,
    offset: u64,
    byte_len: usize,
) -> Result<Vec<u8>> {
    validate_block_artifact_range(role, artifact, offset, byte_len)?;
    let block_size_bytes = artifact.block_size_bytes.ok_or_else(|| {
        PlatformError::conflict(format!("{role} block artifact is missing geometry"))
    })?;
    let block_size_u64 = u64::from(block_size_bytes);
    let end = offset.saturating_add(u64::try_from(byte_len).unwrap_or(u64::MAX));
    let first_block = offset / block_size_u64;
    let last_block = end.saturating_sub(1) / block_size_u64;
    let mut output = Vec::with_capacity(byte_len);
    for block_index in first_block..=last_block {
        let block = read_block_artifact_effective_block(role, artifact, block_index)?;
        let block_start = block_index.saturating_mul(block_size_u64);
        let slice_start = usize::try_from(offset.max(block_start).saturating_sub(block_start))
            .map_err(|_| {
                PlatformError::invalid(format!("{role} slice start exceeds addressability"))
            })?;
        let slice_end = usize::try_from(
            end.min(block_start.saturating_add(block_size_u64))
                .saturating_sub(block_start),
        )
        .map_err(|_| PlatformError::invalid(format!("{role} slice end exceeds addressability")))?;
        output.extend_from_slice(&block[slice_start..slice_end]);
    }
    Ok(output)
}

fn read_block_artifact_effective_block(
    role: &str,
    artifact: &SoftVmBootArtifact,
    block_index: u64,
) -> Result<Vec<u8>> {
    if let Some(overlay) = artifact.overlay.as_ref()
        && let Some(block) = overlay.modified_blocks.get(&block_index)
    {
        return Ok(block.clone());
    }
    read_block_artifact_backing_block(
        role,
        &artifact.source,
        artifact.resolved_local_path.as_deref(),
        artifact.byte_len,
        artifact.block_size_bytes.ok_or_else(|| {
            PlatformError::conflict(format!("{role} block artifact is missing geometry"))
        })?,
        block_index,
    )
}

fn read_block_artifact_backing_block(
    role: &str,
    source: &str,
    resolved_local_path: Option<&str>,
    artifact_byte_len: u64,
    block_size_bytes: u32,
    block_index: u64,
) -> Result<Vec<u8>> {
    let block_size_u64 = u64::from(block_size_bytes);
    let block_size_usize = usize::try_from(block_size_u64)
        .map_err(|_| PlatformError::invalid(format!("{role} block size exceeds usize")))?;
    let block_start = block_index.saturating_mul(block_size_u64);
    let available_len = artifact_byte_len
        .saturating_sub(block_start)
        .min(block_size_u64);
    let available_len_usize = usize::try_from(available_len)
        .map_err(|_| PlatformError::invalid(format!("{role} block window exceeds usize")))?;
    let mut block = vec![0u8; block_size_usize];
    if available_len_usize == 0 {
        return Ok(block);
    }
    let backing = read_block_artifact_backing_range(
        role,
        source,
        resolved_local_path,
        block_start,
        available_len_usize,
    )?;
    block[..available_len_usize].copy_from_slice(&backing);
    Ok(block)
}

fn read_block_artifact_backing_range(
    role: &str,
    source: &str,
    resolved_local_path: Option<&str>,
    offset: u64,
    byte_len: usize,
) -> Result<Vec<u8>> {
    if let Some(path) = resolved_local_path {
        let mut file = File::open(path).map_err(|error| {
            PlatformError::unavailable(format!("failed to open {role} block artifact"))
                .with_detail(error.to_string())
        })?;
        file.seek(SeekFrom::Start(offset)).map_err(|error| {
            PlatformError::unavailable(format!("failed to seek {role} block artifact"))
                .with_detail(error.to_string())
        })?;
        let mut bytes = vec![0u8; byte_len];
        file.read_exact(&mut bytes).map_err(|error| {
            PlatformError::unavailable(format!("failed to read {role} block artifact"))
                .with_detail(error.to_string())
        })?;
        return Ok(bytes);
    }

    let seed = source.as_bytes();
    if seed.is_empty() {
        return Ok(vec![0u8; byte_len]);
    }
    let seed_len = u64::try_from(seed.len())
        .map_err(|_| PlatformError::invalid(format!("{role} source token exceeds u64 size")))?;
    let mut bytes = Vec::with_capacity(byte_len);
    let mut absolute = offset;
    for _ in 0..byte_len {
        let index = usize::try_from(absolute % seed_len)
            .map_err(|_| PlatformError::invalid(format!("{role} seed index exceeds usize")))?;
        bytes.push(seed[index]);
        absolute = absolute.saturating_add(1);
    }
    Ok(bytes)
}

/// Deterministic boot witness synthesized by the software-backed runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmBootWitness {
    /// Boot artifact profile used for boot.
    pub firmware_profile: String,
    /// Initial boot device selected by the runtime.
    pub boot_device: String,
    /// Whether install media is attached.
    pub install_media_attached: bool,
    /// Stable boot stage markers emitted by the runtime.
    pub stages: Vec<String>,
    /// Console-style trace lines describing the boot flow.
    pub console_trace: Vec<String>,
    /// Whether software secure boot was enabled for the boot flow.
    pub secure_boot_enabled: bool,
    /// Deterministic secure-boot measurements emitted during boot.
    pub secure_boot_measurements: Vec<String>,
    /// Whether a guest control channel is considered ready.
    pub guest_control_ready: bool,
}

/// Guest command transport available after the software-backed VM boots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftVmGuestCommandChannel {
    /// Route the command through the serial console path.
    Serial,
    /// Route the command through the virtio-console path.
    VirtioConsole,
    /// Route the command through the guest-agent RPC path.
    GuestAgent,
}

impl SoftVmGuestCommandChannel {
    /// Parse a stable guest-command channel key.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "serial" => Ok(Self::Serial),
            "virtio-console" | "virtio_console" => Ok(Self::VirtioConsole),
            "guest-agent" | "guest_agent" => Ok(Self::GuestAgent),
            _ => Err(PlatformError::invalid(
                "guest command channel must be one of serial/virtio-console/guest-agent",
            )),
        }
    }

    /// Stable guest-command channel key.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Serial => "serial",
            Self::VirtioConsole => "virtio-console",
            Self::GuestAgent => "guest-agent",
        }
    }

    fn delivery_path(self) -> &'static str {
        match self {
            Self::Serial => "uart_console",
            Self::VirtioConsole => "virtio_console",
            Self::GuestAgent => "guest_agent_rpc",
        }
    }

    fn device_loop_name(self) -> Option<&'static str> {
        match self {
            Self::Serial => Some("uart_console"),
            Self::VirtioConsole => Some("virtio_console"),
            Self::GuestAgent => None,
        }
    }
}

fn default_guest_command_channel_key() -> String {
    String::from(SoftVmGuestCommandChannel::Serial.as_str())
}

/// Compatibility file maintained by the legacy guest-control projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmGuestFile {
    /// Absolute in-guest path.
    pub path: String,
    /// Current file contents.
    pub contents: String,
    /// Sparse guest-memory address holding the file bytes.
    pub resident_guest_address: u64,
    /// Resident file byte length.
    pub resident_byte_len: u64,
    /// Fingerprint of the current resident contents.
    pub content_fingerprint: String,
}

/// Synthetic service state maintained by the native guest-control layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmGuestService {
    /// Stable service name.
    pub name: String,
    /// Current service state.
    pub state: String,
}

/// Per-channel command-delivery state maintained by the native guest-control layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmGuestCommandChannelState {
    /// Stable guest-command channel key.
    pub name: String,
    /// Backing transport/device used for the channel.
    pub delivery_path: String,
    /// Current readiness state (`ready` or `unavailable`).
    pub state: String,
    /// Number of request frames/messages sent over the channel.
    pub tx_count: u64,
    /// Number of response frames/messages observed over the channel.
    pub rx_count: u64,
    /// Most recent command sent over the channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_command: Option<String>,
    /// Most recent exit code observed over the channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_exit_code: Option<i32>,
}

/// Result of a command executed by the UVM-native guest-control layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmGuestCommandResult {
    /// Delivery channel used to execute the command.
    #[serde(default = "default_guest_command_channel_key")]
    pub channel: String,
    /// Command string executed inside the native guest-control layer.
    pub command: String,
    /// Exit code returned by the command.
    pub exit_code: i32,
    /// Native execution mode used for the command result.
    pub execution_semantics: String,
    /// Number of interpreted instructions consumed by the command.
    pub instruction_count: u64,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
}

/// Persistent native guest-control session state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmGuestControl {
    /// Synthetic hostname exposed by the guest-control layer.
    pub hostname: String,
    /// Path used as a synthetic readiness marker.
    pub ready_marker_path: String,
    /// Synthetic working directory for the guest session.
    pub cwd: String,
    /// Compatibility projected file-system contents retained for guest-control reads.
    pub files: Vec<SoftVmGuestFile>,
    /// Synthetic service inventory visible from the guest session.
    pub services: Vec<SoftVmGuestService>,
    /// First-class guest command channels and their current delivery state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub channels: Vec<SoftVmGuestCommandChannelState>,
    /// Number of UnixBench-style benchmark runs triggered through guest control.
    pub benchmark_runs: u32,
    /// Previously executed commands and their results.
    pub history: Vec<SoftVmGuestCommandResult>,
}

/// Minimal heartbeat emitted by the software-backed VM skeleton.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmHeartbeat {
    /// Runtime phase.
    pub phase: String,
    /// Total guest memory in bytes.
    pub guest_memory_bytes: u64,
    /// Guest vCPU count.
    pub vcpu: u16,
    /// Backend key.
    pub backend: String,
    /// Monotonic heartbeat sequence.
    pub sequence: u64,
}

/// Minimal in-process software-backed VM skeleton.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftVmInstance {
    /// Current lifecycle phase.
    pub phase: SoftVmPhase,
    /// Runtime spec.
    pub spec: SoftVmRuntimeSpec,
    /// Memory layout.
    pub memory: MemoryLayout,
    /// Internal native execution core.
    pub execution: SoftVmExecutionCore,
    /// Most recent boot witness once the runtime has started.
    pub boot_witness: Option<SoftVmBootWitness>,
    /// Persistent native guest-control session available after boot.
    pub guest_control: Option<SoftVmGuestControl>,
    /// Cached resident programs for normalized guest commands.
    pub guest_command_programs: BTreeMap<String, SoftVmResidentProgram>,
    /// Monotonic heartbeat sequence.
    pub heartbeat_sequence: u64,
}

impl SoftVmInstance {
    /// Construct a new software-backed VM skeleton from a runtime spec.
    pub fn new(spec: SoftVmRuntimeSpec) -> Result<Self> {
        Self::new_with_artifact_policy(spec, SoftVmArtifactPolicy::CatalogPreviewAllowed)
    }

    /// Construct a new software-backed VM skeleton from a runtime spec under an explicit artifact policy.
    pub fn new_with_artifact_policy(
        spec: SoftVmRuntimeSpec,
        artifact_policy: SoftVmArtifactPolicy,
    ) -> Result<Self> {
        let memory = spec.machine.memory_layout()?;
        let execution =
            SoftVmExecutionCore::from_spec_with_artifact_policy(&spec, &memory, artifact_policy)?;
        Ok(Self {
            phase: SoftVmPhase::Created,
            memory,
            execution,
            spec,
            boot_witness: None,
            guest_control: None,
            guest_command_programs: BTreeMap::new(),
            heartbeat_sequence: 0,
        })
    }

    /// Prepare the runtime skeleton.
    pub fn prepare(&mut self) -> Result<()> {
        if self.phase != SoftVmPhase::Created {
            return Err(PlatformError::conflict(
                "software-backed VM may only be prepared from created state",
            ));
        }
        self.phase = SoftVmPhase::Prepared;
        Ok(())
    }

    /// Start the runtime skeleton.
    pub fn start(&mut self) -> Result<()> {
        if direct_kernel_boot(&self.spec) {
            ensure_local_execution_artifact("kernel", self.spec.firmware_artifact_source())?;
        }
        ensure_local_execution_artifact("primary_disk", &self.spec.machine.boot.disk_image)?;
        if let Some(cdrom_image) = self.spec.machine.boot.cdrom_image.as_deref() {
            ensure_local_execution_artifact("install_media", cdrom_image)?;
        }
        match self.phase {
            SoftVmPhase::Created => self.prepare()?,
            SoftVmPhase::Prepared | SoftVmPhase::Stopped => {}
            SoftVmPhase::Running => {
                return Err(PlatformError::conflict(
                    "software-backed VM is already running",
                ));
            }
        }
        self.phase = SoftVmPhase::Running;
        self.boot_witness = Some(self.execution.run_boot_sequence(&self.spec));
        self.guest_control = Some(self.initialize_guest_control()?);
        Ok(())
    }

    /// Stop the runtime skeleton.
    pub fn stop(&mut self) -> Result<()> {
        if self.phase != SoftVmPhase::Running {
            return Err(PlatformError::conflict(
                "software-backed VM may only be stopped from running state",
            ));
        }
        self.phase = SoftVmPhase::Stopped;
        Ok(())
    }

    /// Emit a deterministic heartbeat from the runtime skeleton.
    pub fn heartbeat(&mut self) -> SoftVmHeartbeat {
        self.heartbeat_sequence = self.heartbeat_sequence.saturating_add(1);
        SoftVmHeartbeat {
            phase: String::from(self.phase.as_str()),
            guest_memory_bytes: self.memory.guest_memory_bytes,
            vcpu: self.spec.machine.vcpu,
            backend: String::from(HypervisorBackend::SoftwareDbt.as_str()),
            sequence: self.heartbeat_sequence,
        }
    }

    /// Return the synthesized boot witness after the runtime has started.
    pub fn boot_witness(&self) -> Result<SoftVmBootWitness> {
        self.boot_witness.clone().ok_or_else(|| {
            PlatformError::conflict(
                "software-backed VM has not produced a boot witness before entering running state",
            )
        })
    }

    /// Return the persistent guest-control view after the runtime has started.
    pub fn guest_control(&self) -> Result<SoftVmGuestControl> {
        let mut control = self.guest_control.clone().ok_or_else(|| {
            PlatformError::conflict(
                "software-backed VM has not created a guest-control session before entering running state",
            )
        })?;
        sync_guest_command_channel_views(&self.execution, &mut control);
        Ok(control)
    }

    /// Execute a command within the UVM-native guest-control layer.
    pub fn run_guest_command(&mut self, command: &str) -> Result<SoftVmGuestCommandResult> {
        let (channel, normalized) = parse_guest_command_request(command)?;
        self.run_guest_command_via(channel, normalized.as_str())
    }

    /// Execute a command within the UVM-native guest-control layer over a specific channel.
    pub fn run_guest_command_via(
        &mut self,
        channel: SoftVmGuestCommandChannel,
        command: &str,
    ) -> Result<SoftVmGuestCommandResult> {
        if self.phase != SoftVmPhase::Running {
            return Err(PlatformError::conflict(
                "software-backed VM may only execute guest commands while running",
            ));
        }
        let normalized = normalize_guest_command(command)?;
        let guest_architecture = self.spec.machine.guest_architecture.clone();
        let vcpu = self.spec.machine.vcpu;
        let guest_memory_bytes = self.memory.guest_memory_bytes;
        let mut control = self.guest_control.take().ok_or_else(|| {
            PlatformError::conflict(
                "software-backed VM has not created a guest-control session before entering running state",
            )
        })?;
        sync_guest_command_channel_views(&self.execution, &mut control);
        ensure_guest_command_channel_ready(&self.execution, &control.history, channel)?;
        let program = match self.guest_command_program(&normalized) {
            Ok(program) => program,
            Err(error) => {
                self.guest_control = Some(control);
                return Err(error);
            }
        };
        if let Err(error) =
            record_guest_command_channel_dispatch(&mut self.execution, channel, normalized.as_str())
        {
            self.guest_control = Some(control);
            return Err(error);
        }
        let outcome = match self.execution.execute_guest_program(
            &program,
            &guest_architecture,
            vcpu,
            guest_memory_bytes,
            &mut control,
        ) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.guest_control = Some(control);
                return Err(error);
            }
        };
        let result = SoftVmGuestCommandResult {
            channel: String::from(channel.as_str()),
            command: normalized,
            exit_code: outcome.exit_code,
            execution_semantics: String::from("interpreted_guest_isa_v0"),
            instruction_count: outcome.instruction_count,
            stdout: outcome.stdout,
            stderr: outcome.stderr,
        };
        record_guest_command_channel_completion(&mut self.execution, &result)?;
        control.history.push(result.clone());
        sync_guest_command_channel_views(&self.execution, &mut control);
        self.guest_control = Some(control);
        Ok(result)
    }

    fn guest_command_program(&mut self, normalized: &str) -> Result<SoftVmResidentProgram> {
        // This resident-program cache is keyed by normalized command text so
        // repeated guest-control commands can reuse compiled bytecode and keep
        // the decode/trace caches warm across invocations.
        if let Some(program) = self.guest_command_programs.get(normalized) {
            self.execution
                .completed_events
                .push(SoftVmExecutionEvent::new(
                    "guest_command_cache_hit",
                    format!("reused resident guest command for `{normalized}`"),
                ));
            return Ok(program.clone());
        }
        let program_name = format!(
            "guest_command_{:04}",
            self.guest_command_programs.len().saturating_add(1)
        );
        let bytecode = self.compile_guest_command_bytecode(normalized, &program_name)?;
        let program =
            self.execution
                .register_resident_program(program_name, "guest_ram", bytecode)?;
        self.execution
            .completed_events
            .push(SoftVmExecutionEvent::new(
                "guest_command_cache_miss",
                format!("compiled resident guest command for `{normalized}`"),
            ));
        self.guest_command_programs
            .insert(normalized.to_owned(), program.clone());
        Ok(program)
    }

    fn initialize_guest_control(&mut self) -> Result<SoftVmGuestControl> {
        let hostname = format!("uvm-native-{}", self.spec.machine.guest_architecture);
        let ready_marker_path = String::from("/var/tmp/uhost-native-ready");
        let services = guest_control_services(&self.spec);
        let direct_kernel_projections = self
            .execution
            .direct_kernel_state
            .as_ref()
            .map(|state| direct_kernel_guest_control_projections(&self.execution, state))
            .unwrap_or_default();
        let files = materialize_guest_file_projections(
            &mut self.execution,
            guest_control_file_projections(
                &self.spec,
                self.memory.guest_memory_bytes,
                &hostname,
                &ready_marker_path,
                self.boot_witness.as_ref(),
                &direct_kernel_projections,
                &services,
            ),
        )?;
        let mut control = SoftVmGuestControl {
            hostname,
            ready_marker_path,
            cwd: String::from("/"),
            files,
            services,
            channels: Vec::new(),
            benchmark_runs: 0,
            history: Vec::new(),
        };
        refresh_guest_network_views(&mut self.execution, &mut control.files, &control.hostname)?;
        sync_guest_command_channel_views(&self.execution, &mut control);
        Ok(control)
    }

    fn compile_guest_command_bytecode(
        &mut self,
        command: &str,
        program_name: &str,
    ) -> Result<Vec<u8>> {
        let mut bytecode = Vec::new();
        match command {
            "uname -a" => self.emit_guest_kernel_call(
                &mut bytecode,
                program_name,
                NATIVE_CALL_GUEST_UNAME,
                None,
                None,
            )?,
            "ip addr" => self.emit_guest_kernel_call(
                &mut bytecode,
                program_name,
                NATIVE_CALL_GUEST_CAT,
                Some(b"/run/guest-network/ip-addr"),
                None,
            )?,
            "ip route" => self.emit_guest_kernel_call(
                &mut bytecode,
                program_name,
                NATIVE_CALL_GUEST_CAT,
                Some(b"/run/guest-network/ip-route"),
                None,
            )?,
            "hostname -I" => self.emit_guest_kernel_call(
                &mut bytecode,
                program_name,
                NATIVE_CALL_GUEST_CAT,
                Some(b"/run/guest-network/hostname-i"),
                None,
            )?,
            "resolvectl status" => self.emit_guest_kernel_call(
                &mut bytecode,
                program_name,
                NATIVE_CALL_GUEST_CAT,
                Some(b"/run/guest-network/resolvectl-status"),
                None,
            )?,
            "ss -ltn" => self.emit_guest_kernel_call(
                &mut bytecode,
                program_name,
                NATIVE_CALL_GUEST_CAT,
                Some(b"/run/guest-network/ss-ltn"),
                None,
            )?,
            "ss -lun" => self.emit_guest_kernel_call(
                &mut bytecode,
                program_name,
                NATIVE_CALL_GUEST_CAT,
                Some(b"/run/guest-network/ss-lun"),
                None,
            )?,
            "systemctl is-system-running" => self.emit_guest_kernel_call(
                &mut bytecode,
                program_name,
                NATIVE_CALL_GUEST_SYSTEM_STATE,
                None,
                None,
            )?,
            "unixbench --summary" | "unixbench" => self.emit_guest_kernel_call(
                &mut bytecode,
                program_name,
                NATIVE_CALL_GUEST_UNIXBENCH,
                None,
                None,
            )?,
            _ if command.starts_with("nslookup ") || command.starts_with("getent ") => {
                let (mode, host) = parse_guest_dns_lookup_command(command)?;
                self.emit_guest_kernel_call(
                    &mut bytecode,
                    program_name,
                    NATIVE_CALL_GUEST_DNS_LOOKUP,
                    Some(host.as_bytes()),
                    Some(mode.as_str().as_bytes()),
                )?;
            }
            _ if command.starts_with("curl ") || command.starts_with("fetch ") => {
                let request = parse_guest_egress_command(command)?;
                self.emit_guest_kernel_call(
                    &mut bytecode,
                    program_name,
                    NATIVE_CALL_GUEST_HTTP_FETCH,
                    Some(request.url.as_bytes()),
                    Some(request.method.as_str().as_bytes()),
                )?;
            }
            _ if command.starts_with("nc ") || command.starts_with("netcat ") => {
                if command
                    .split_whitespace()
                    .any(|token| token.starts_with('-') && token.contains('u'))
                {
                    let request = parse_guest_udp_exchange_command(command)?;
                    let target = request.target();
                    let mode = request.wire_mode();
                    self.emit_guest_kernel_call(
                        &mut bytecode,
                        program_name,
                        NATIVE_CALL_GUEST_UDP_EXCHANGE,
                        Some(target.as_bytes()),
                        Some(mode.as_bytes()),
                    )?;
                } else {
                    let request = parse_guest_tcp_connect_command(command)?;
                    let target = request.target();
                    let mode = request.wire_mode();
                    self.emit_guest_kernel_call(
                        &mut bytecode,
                        program_name,
                        NATIVE_CALL_GUEST_TCP_CONNECT,
                        Some(target.as_bytes()),
                        Some(mode.as_bytes()),
                    )?;
                }
            }
            _ if command.starts_with("systemctl status ") => {
                let service_name = command
                    .strip_prefix("systemctl status")
                    .map(str::trim)
                    .ok_or_else(|| PlatformError::invalid("invalid systemctl status command"))?;
                if service_name.is_empty() {
                    return Err(PlatformError::invalid(
                        "systemctl status requires a service name",
                    ));
                }
                self.emit_guest_kernel_call(
                    &mut bytecode,
                    program_name,
                    NATIVE_CALL_GUEST_SYSTEMCTL_STATUS,
                    Some(service_name.as_bytes()),
                    None,
                )?;
            }
            _ if command.starts_with("cat ") => {
                let path = normalize_guest_path(
                    command
                        .strip_prefix("cat")
                        .map(str::trim)
                        .ok_or_else(|| PlatformError::invalid("invalid cat command"))?,
                )?;
                self.emit_guest_kernel_call(
                    &mut bytecode,
                    program_name,
                    NATIVE_CALL_GUEST_CAT,
                    Some(path.as_bytes()),
                    None,
                )?;
            }
            _ if command.starts_with("echo ") && command.contains('>') => {
                let (left, right) = command
                    .split_once('>')
                    .ok_or_else(|| PlatformError::invalid("echo redirection requires `>`"))?;
                let payload = left
                    .strip_prefix("echo")
                    .map(str::trim)
                    .ok_or_else(|| PlatformError::invalid("invalid echo command"))?;
                let path = normalize_guest_path(right.trim())?;
                self.emit_guest_kernel_call(
                    &mut bytecode,
                    program_name,
                    NATIVE_CALL_GUEST_ECHO_REDIRECT,
                    Some(path.as_bytes()),
                    Some(strip_wrapping_quotes(payload).as_bytes()),
                )?;
            }
            _ if command.starts_with("touch ") => {
                let path = normalize_guest_path(
                    command
                        .strip_prefix("touch")
                        .map(str::trim)
                        .ok_or_else(|| PlatformError::invalid("invalid touch command"))?,
                )?;
                self.emit_guest_kernel_call(
                    &mut bytecode,
                    program_name,
                    NATIVE_CALL_GUEST_TOUCH,
                    Some(path.as_bytes()),
                    None,
                )?;
            }
            _ if command.starts_with("ls ") => {
                let path = normalize_guest_path(
                    command
                        .strip_prefix("ls")
                        .map(str::trim)
                        .ok_or_else(|| PlatformError::invalid("invalid ls command"))?,
                )?;
                self.emit_guest_kernel_call(
                    &mut bytecode,
                    program_name,
                    NATIVE_CALL_GUEST_LS,
                    Some(path.as_bytes()),
                    None,
                )?;
            }
            _ if command.starts_with("sha256sum ") => {
                let path = normalize_guest_path(
                    command
                        .strip_prefix("sha256sum")
                        .map(str::trim)
                        .ok_or_else(|| PlatformError::invalid("invalid sha256sum command"))?,
                )?;
                self.emit_guest_kernel_call(
                    &mut bytecode,
                    program_name,
                    NATIVE_CALL_GUEST_SHA256SUM,
                    Some(path.as_bytes()),
                    None,
                )?;
            }
            _ => {
                self.emit_guest_kernel_call(
                    &mut bytecode,
                    program_name,
                    NATIVE_CALL_GUEST_UNSUPPORTED,
                    Some(b"unsupported guest command under native executor"),
                    None,
                )?;
            }
        }
        emit_halt(&mut bytecode);
        Ok(bytecode)
    }

    fn emit_guest_kernel_call(
        &mut self,
        bytecode: &mut Vec<u8>,
        program_name: &str,
        operation: u8,
        arg0: Option<&[u8]>,
        arg1: Option<&[u8]>,
    ) -> Result<()> {
        let (arg0_addr, arg0_len) = if let Some(bytes) = arg0 {
            let allocation = self
                .execution
                .allocate_guest_data(format!("data:{program_name}:arg0"), bytes)?;
            (allocation.guest_address, allocation.byte_len)
        } else {
            (0, 0)
        };
        let (arg1_addr, arg1_len) = if let Some(bytes) = arg1 {
            let allocation = self
                .execution
                .allocate_guest_data(format!("data:{program_name}:arg1"), bytes)?;
            (allocation.guest_address, allocation.byte_len)
        } else {
            (0, 0)
        };
        let request_bytes =
            encode_guest_kernel_request(operation, arg0_addr, arg0_len, arg1_addr, arg1_len);
        let request = self.execution.allocate_guest_data(
            format!("data:{program_name}:kernel_request"),
            &request_bytes,
        )?;
        let service = guest_kernel_service_descriptor(&self.execution, operation)?;
        emit_mov_imm64(bytecode, ISA_REGISTER_ARG0, request.guest_address);
        emit_call_abs64(bytecode, service.entry_point);
        Ok(())
    }
}

fn build_boot_program(
    spec: &SoftVmRuntimeSpec,
    reset_vector: u64,
    boot_service: &SoftVmResidentProgram,
) -> Result<SoftVmResidentProgram> {
    let mut bytecode = Vec::new();
    for boot_stage in boot_service_stage_sequence(spec) {
        emit_call_abs64(
            &mut bytecode,
            boot_service_handler_entry_point(boot_service, boot_stage)?,
        );
    }
    emit_halt(&mut bytecode);
    Ok(SoftVmResidentProgram::new(
        "boot_dispatch",
        boot_code_region_name(spec),
        reset_vector,
        bytecode,
    ))
}

fn build_boot_service_program(
    spec: &SoftVmRuntimeSpec,
    topology: &MachineTopology,
    entry_point: u64,
) -> Result<SoftVmResidentProgram> {
    let handlers = boot_service_stage_sequence(spec)
        .into_iter()
        .map(|call_id| Ok((call_id, build_boot_service_handler(topology, call_id)?)))
        .collect::<Result<Vec<_>>>()?;
    let mut bytecode = Vec::new();
    bytecode.push(BOOT_SERVICE_VERSION);
    bytecode.push(u8::try_from(handlers.len()).unwrap_or(u8::MAX));
    let mut handler_offset = u64::try_from(
        2usize.saturating_add(handlers.len().saturating_mul(BOOT_SERVICE_DESCRIPTOR_BYTES)),
    )
    .unwrap_or(u64::MAX);
    for (call_id, handler) in &handlers {
        bytecode.push(*call_id);
        bytecode.extend_from_slice(&handler_offset.to_le_bytes());
        handler_offset =
            handler_offset.saturating_add(u64::try_from(handler.len()).unwrap_or(u64::MAX));
    }
    for (_, handler) in handlers {
        bytecode.extend_from_slice(&handler);
    }
    Ok(SoftVmResidentProgram::new(
        "boot_service",
        boot_code_region_name(spec),
        entry_point,
        bytecode,
    ))
}

fn build_boot_service_handler(topology: &MachineTopology, call_id: u8) -> Result<Vec<u8>> {
    let mut bytecode = Vec::new();
    if let Some(mmio_write) = boot_service_stage_descriptor(call_id)
        .and_then(|descriptor| descriptor.pre_dispatch_mmio_write)
    {
        let guest_physical_address = topology
            .device_by_kind(mmio_write.device_kind)
            .map(|device| device.guest_physical_base)
            .ok_or_else(|| {
                PlatformError::conflict(format!(
                    "machine topology is missing `{}` device",
                    mmio_write.device_kind
                ))
            })?;
        emit_mmio_write64(&mut bytecode, guest_physical_address, mmio_write.value);
    }
    emit_mov_imm64(&mut bytecode, ISA_REGISTER_ARG1, u64::from(call_id));
    emit_native_call(&mut bytecode, NATIVE_CALL_BOOT_SERVICE_ROUTE);
    emit_ret(&mut bytecode);
    Ok(bytecode)
}

fn boot_service_handler_entry_point(program: &SoftVmResidentProgram, call_id: u8) -> Result<u64> {
    let version = *program
        .bytecode
        .first()
        .ok_or_else(|| PlatformError::unavailable("boot-service program is empty"))?;
    if version != BOOT_SERVICE_VERSION {
        return Err(PlatformError::conflict(
            "boot-service program version is unsupported",
        ));
    }
    let entry_count = usize::from(
        *program
            .bytecode
            .get(1)
            .ok_or_else(|| PlatformError::unavailable("boot-service entry count is missing"))?,
    );
    let mut cursor = 2usize;
    for _ in 0..entry_count {
        let declared_call_id = *program
            .bytecode
            .get(cursor)
            .ok_or_else(|| PlatformError::unavailable("boot-service entry is truncated"))?;
        let handler_offset = program
            .bytecode
            .get(cursor.saturating_add(1)..cursor.saturating_add(BOOT_SERVICE_DESCRIPTOR_BYTES))
            .ok_or_else(|| PlatformError::unavailable("boot-service handler offset is truncated"))?
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| PlatformError::unavailable("boot-service handler offset is invalid"))?;
        if declared_call_id == call_id {
            return Ok(program.entry_point.saturating_add(handler_offset));
        }
        cursor = cursor.saturating_add(BOOT_SERVICE_DESCRIPTOR_BYTES);
    }
    Err(PlatformError::conflict(
        "boot-service program does not declare the requested stage",
    ))
}

fn boot_service_stage_sequence(spec: &SoftVmRuntimeSpec) -> Vec<u8> {
    // The stage sequence plus the descriptor table below define the canonical
    // boot pipeline for both firmware and direct-kernel paths, including any
    // required pre-dispatch MMIO setup before the boot service hands control to
    // the next stage.
    let mut stages = vec![if direct_kernel_boot(spec) {
        NATIVE_CALL_DIRECT_KERNEL_ENTRY
    } else {
        NATIVE_CALL_FIRMWARE_DISPATCH
    }];
    if spec.machine.boot.cdrom_image.is_some() {
        stages.push(NATIVE_CALL_INSTALL_MEDIA_PROBE);
    }
    stages.push(NATIVE_CALL_BOOT_DEVICE_TRANSFER);
    stages.push(NATIVE_CALL_USERSPACE_CONTROL);
    stages
}

const BOOT_SERVICE_STAGE_DESCRIPTORS: &[BootServiceStageDescriptor] = &[
    BootServiceStageDescriptor {
        call_id: NATIVE_CALL_FIRMWARE_DISPATCH,
        effect: BootServiceStageEffect::FirmwareDispatch,
        pre_dispatch_mmio_write: None,
    },
    BootServiceStageDescriptor {
        call_id: NATIVE_CALL_DIRECT_KERNEL_ENTRY,
        effect: BootServiceStageEffect::DirectKernelEntry,
        pre_dispatch_mmio_write: None,
    },
    BootServiceStageDescriptor {
        call_id: NATIVE_CALL_INSTALL_MEDIA_PROBE,
        effect: BootServiceStageEffect::InstallMediaProbe,
        pre_dispatch_mmio_write: Some(BootServiceMmioWriteDescriptor {
            device_kind: "block_control",
            value: 1,
        }),
    },
    BootServiceStageDescriptor {
        call_id: NATIVE_CALL_BOOT_DEVICE_TRANSFER,
        effect: BootServiceStageEffect::BootDeviceTransfer,
        pre_dispatch_mmio_write: Some(BootServiceMmioWriteDescriptor {
            device_kind: "block_control",
            value: NATIVE_CALL_BOOT_DEVICE_TRANSFER as u64,
        }),
    },
    BootServiceStageDescriptor {
        call_id: NATIVE_CALL_USERSPACE_CONTROL,
        effect: BootServiceStageEffect::UserspaceControl,
        pre_dispatch_mmio_write: Some(BootServiceMmioWriteDescriptor {
            device_kind: "console",
            value: 1,
        }),
    },
];

fn boot_service_stage_descriptor(call_id: u8) -> Option<BootServiceStageDescriptor> {
    BOOT_SERVICE_STAGE_DESCRIPTORS
        .iter()
        .copied()
        .find(|descriptor| descriptor.call_id == call_id)
}

fn build_guest_kernel_service_program(entry_point: u64) -> SoftVmResidentProgram {
    let handlers = GUEST_KERNEL_SERVICE_ENTRIES
        .iter()
        .copied()
        .map(|descriptor| {
            (
                descriptor,
                build_guest_kernel_service_handler(
                    descriptor.operation,
                    descriptor.kind,
                    descriptor.route,
                ),
            )
        })
        .collect::<Vec<_>>();
    let mut bytecode = Vec::new();
    bytecode.push(GUEST_KERNEL_SERVICE_VERSION);
    bytecode.push(u8::try_from(handlers.len()).unwrap_or(u8::MAX));
    let mut handler_offset = u64::try_from(
        2usize.saturating_add(
            handlers
                .len()
                .saturating_mul(GUEST_KERNEL_SERVICE_DESCRIPTOR_BYTES),
        ),
    )
    .unwrap_or(u64::MAX);
    for (descriptor, handler) in &handlers {
        bytecode.push(descriptor.operation);
        bytecode.push(descriptor.kind);
        bytecode.push(descriptor.route);
        bytecode.extend_from_slice(&handler_offset.to_le_bytes());
        handler_offset =
            handler_offset.saturating_add(u64::try_from(handler.len()).unwrap_or(u64::MAX));
    }
    for (_, handler) in handlers {
        bytecode.extend_from_slice(&handler);
    }
    SoftVmResidentProgram::new("guest_kernel_service", "guest_ram", entry_point, bytecode)
}

fn build_guest_kernel_service_handler(operation: u8, kind: u8, route: u8) -> Vec<u8> {
    let mut bytecode = Vec::new();
    emit_mov_imm64(&mut bytecode, ISA_REGISTER_ARG1, u64::from(kind));
    emit_mov_imm64(&mut bytecode, ISA_REGISTER_ARG2, u64::from(route));
    emit_mov_imm64(&mut bytecode, ISA_REGISTER_ARG3, u64::from(operation));
    emit_native_call(&mut bytecode, NATIVE_CALL_GUEST_SERVICE_ROUTE);
    emit_ret(&mut bytecode);
    bytecode
}

fn guest_kernel_service_descriptor(
    execution: &SoftVmExecutionCore,
    operation: u8,
) -> Result<GuestKernelServiceDescriptor> {
    let program = execution.resident_program_named("guest_kernel_service")?;
    let version = *program
        .bytecode
        .first()
        .ok_or_else(|| PlatformError::unavailable("guest-kernel service program is empty"))?;
    if version != GUEST_KERNEL_SERVICE_VERSION {
        return Err(PlatformError::conflict(
            "guest-kernel service program version is unsupported",
        ));
    }
    let entry_count = usize::from(*program.bytecode.get(1).ok_or_else(|| {
        PlatformError::unavailable("guest-kernel service entry count is missing")
    })?);
    let mut cursor = 2usize;
    for _ in 0..entry_count {
        let declared_operation = *program
            .bytecode
            .get(cursor)
            .ok_or_else(|| PlatformError::unavailable("guest-kernel service entry is truncated"))?;
        let kind = *program
            .bytecode
            .get(cursor.saturating_add(1))
            .ok_or_else(|| PlatformError::unavailable("guest-kernel service kind is truncated"))?;
        let route = *program
            .bytecode
            .get(cursor.saturating_add(2))
            .ok_or_else(|| PlatformError::unavailable("guest-kernel service route is truncated"))?;
        let handler_offset = program
            .bytecode
            .get(
                cursor.saturating_add(3)
                    ..cursor.saturating_add(GUEST_KERNEL_SERVICE_DESCRIPTOR_BYTES),
            )
            .ok_or_else(|| {
                PlatformError::unavailable("guest-kernel service handler offset is truncated")
            })?
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| {
                PlatformError::unavailable("guest-kernel service handler offset is invalid")
            })?;
        if declared_operation == operation {
            return Ok(GuestKernelServiceDescriptor {
                operation: GuestKernelOperationDescriptor {
                    operation: declared_operation,
                    kind,
                    route,
                },
                entry_point: program.entry_point.saturating_add(handler_offset),
            });
        }
        cursor = cursor.saturating_add(GUEST_KERNEL_SERVICE_DESCRIPTOR_BYTES);
    }
    Err(PlatformError::conflict(
        "guest-kernel service program does not declare the requested operation",
    ))
}

fn guest_kernel_required_file_route(
    route: u8,
    path: &'static str,
    unavailable_message: &'static str,
) -> GuestKernelRouteDescriptor {
    GuestKernelRouteDescriptor {
        route,
        dispatch: GuestKernelRouteDispatch::RequiredFile {
            path,
            unavailable_message,
        },
    }
}

fn guest_kernel_lookup_route(
    route: u8,
    resolve: GuestKernelLookupResolver,
    exit_code: i32,
    stderr: GuestKernelMissingFormatter,
    treat_empty_as_missing: bool,
) -> GuestKernelRouteDescriptor {
    GuestKernelRouteDescriptor {
        route,
        dispatch: GuestKernelRouteDispatch::LookupFile {
            resolve,
            missing: GuestKernelLookupMissingBehavior {
                exit_code,
                stderr,
                treat_empty_as_missing,
            },
        },
    }
}

fn guest_kernel_mutation_route(
    route: u8,
    behavior: GuestKernelMutationBehavior,
) -> GuestKernelRouteDescriptor {
    GuestKernelRouteDescriptor {
        route,
        dispatch: GuestKernelRouteDispatch::Mutation(behavior),
    }
}

fn guest_kernel_service_status_lookup(
    execution: &SoftVmExecutionCore,
    invocation: &GuestKernelRouteInvocation,
) -> Result<GuestKernelResolvedLookup> {
    let service_name = invocation.read_arg0(execution)?;
    let status_path = format!("/run/systemd/services/{}.status", service_name);
    Ok(GuestKernelResolvedLookup::new(service_name, status_path))
}

fn guest_kernel_direct_path_lookup(
    execution: &SoftVmExecutionCore,
    invocation: &GuestKernelRouteInvocation,
) -> Result<GuestKernelResolvedLookup> {
    Ok(GuestKernelResolvedLookup::direct(
        invocation.read_arg0(execution)?,
    ))
}

fn guest_kernel_directory_index_lookup(
    execution: &SoftVmExecutionCore,
    invocation: &GuestKernelRouteInvocation,
) -> Result<GuestKernelResolvedLookup> {
    let path = invocation.read_arg0(execution)?;
    Ok(GuestKernelResolvedLookup::new(
        path.clone(),
        guest_directory_index_path(&path),
    ))
}

fn guest_kernel_sha256_index_lookup(
    execution: &SoftVmExecutionCore,
    invocation: &GuestKernelRouteInvocation,
) -> Result<GuestKernelResolvedLookup> {
    let path = invocation.read_arg0(execution)?;
    Ok(GuestKernelResolvedLookup::new(
        path.clone(),
        guest_sha256_index_path(&path),
    ))
}

fn guest_kernel_missing_service_status(subject: &str) -> String {
    format!("Unit {subject}.service could not be found.\n")
}

fn guest_kernel_missing_file_read(subject: &str) -> String {
    format!("cat: {subject}: No such file or directory\n")
}

fn guest_kernel_missing_directory_index(subject: &str) -> String {
    format!("ls: cannot access '{subject}': No such file or directory\n")
}

fn guest_kernel_missing_sha256_index(subject: &str) -> String {
    format!("sha256sum: {subject}: No such file or directory\n")
}

fn guest_kernel_route_descriptor(route: u8) -> Option<GuestKernelRouteDescriptor> {
    [
        guest_kernel_required_file_route(
            GUEST_KERNEL_ROUTE_FIXED_UNAME,
            "/proc/sys/kernel/uname",
            "missing synthetic uname guest artifact",
        ),
        guest_kernel_required_file_route(
            GUEST_KERNEL_ROUTE_FIXED_SYSTEM_STATE,
            "/run/system-state",
            "missing synthetic system-state guest artifact",
        ),
        guest_kernel_lookup_route(
            GUEST_KERNEL_ROUTE_SERVICE_STATUS,
            guest_kernel_service_status_lookup,
            4,
            guest_kernel_missing_service_status,
            false,
        ),
        guest_kernel_lookup_route(
            GUEST_KERNEL_ROUTE_FILE_READ,
            guest_kernel_direct_path_lookup,
            1,
            guest_kernel_missing_file_read,
            false,
        ),
        guest_kernel_mutation_route(
            GUEST_KERNEL_ROUTE_FILE_WRITE,
            GuestKernelMutationBehavior::WritePayloadWithTrailingNewline,
        ),
        guest_kernel_mutation_route(
            GUEST_KERNEL_ROUTE_FILE_TOUCH,
            GuestKernelMutationBehavior::TouchIfMissing,
        ),
        guest_kernel_lookup_route(
            GUEST_KERNEL_ROUTE_DIRECTORY_INDEX,
            guest_kernel_directory_index_lookup,
            2,
            guest_kernel_missing_directory_index,
            true,
        ),
        guest_kernel_lookup_route(
            GUEST_KERNEL_ROUTE_SHA256_INDEX,
            guest_kernel_sha256_index_lookup,
            1,
            guest_kernel_missing_sha256_index,
            true,
        ),
        GuestKernelRouteDescriptor {
            route: GUEST_KERNEL_ROUTE_UNIXBENCH,
            dispatch: GuestKernelRouteDispatch::BenchmarkSummary,
        },
        GuestKernelRouteDescriptor {
            route: GUEST_KERNEL_ROUTE_ERROR,
            dispatch: GuestKernelRouteDispatch::ErrorResult,
        },
        GuestKernelRouteDescriptor {
            route: GUEST_KERNEL_ROUTE_HTTP_FETCH,
            dispatch: GuestKernelRouteDispatch::HttpFetch,
        },
        GuestKernelRouteDescriptor {
            route: GUEST_KERNEL_ROUTE_TCP_CONNECT,
            dispatch: GuestKernelRouteDispatch::TcpConnect,
        },
        GuestKernelRouteDescriptor {
            route: GUEST_KERNEL_ROUTE_DNS_LOOKUP,
            dispatch: GuestKernelRouteDispatch::DnsLookup,
        },
        GuestKernelRouteDescriptor {
            route: GUEST_KERNEL_ROUTE_UDP_EXCHANGE,
            dispatch: GuestKernelRouteDispatch::UdpExchange,
        },
    ]
    .into_iter()
    .find(|descriptor| descriptor.route == route)
}

fn guest_kernel_service_kind_name(kind: u8) -> &'static str {
    match kind {
        GUEST_KERNEL_SERVICE_KIND_READ_ONLY => "read_only",
        GUEST_KERNEL_SERVICE_KIND_MUTATION => "mutation",
        GUEST_KERNEL_SERVICE_KIND_INDEX => "index",
        GUEST_KERNEL_SERVICE_KIND_BENCHMARK => "benchmark",
        GUEST_KERNEL_SERVICE_KIND_ERROR => "error",
        GUEST_KERNEL_SERVICE_KIND_NETWORK => "network",
        _ => "unknown_service_kind",
    }
}

fn guest_kernel_service_route_name(route: u8) -> &'static str {
    match route {
        GUEST_KERNEL_ROUTE_FIXED_UNAME => "fixed_uname",
        GUEST_KERNEL_ROUTE_FIXED_SYSTEM_STATE => "fixed_system_state",
        GUEST_KERNEL_ROUTE_SERVICE_STATUS => "service_status",
        GUEST_KERNEL_ROUTE_FILE_READ => "file_read",
        GUEST_KERNEL_ROUTE_FILE_WRITE => "file_write",
        GUEST_KERNEL_ROUTE_FILE_TOUCH => "file_touch",
        GUEST_KERNEL_ROUTE_DIRECTORY_INDEX => "directory_index",
        GUEST_KERNEL_ROUTE_SHA256_INDEX => "sha256_index",
        GUEST_KERNEL_ROUTE_UNIXBENCH => "unixbench",
        GUEST_KERNEL_ROUTE_ERROR => "error",
        GUEST_KERNEL_ROUTE_HTTP_FETCH => "http_fetch",
        GUEST_KERNEL_ROUTE_TCP_CONNECT => "tcp_connect",
        GUEST_KERNEL_ROUTE_DNS_LOOKUP => "dns_lookup",
        GUEST_KERNEL_ROUTE_UDP_EXCHANGE => "udp_exchange",
        _ => "unknown_service_route",
    }
}

fn emit_mov_imm64(bytecode: &mut Vec<u8>, register: u8, immediate: u64) {
    bytecode.push(ISA_OPCODE_MOV_IMM64);
    bytecode.push(register);
    bytecode.extend_from_slice(&immediate.to_le_bytes());
}

fn emit_native_call(bytecode: &mut Vec<u8>, call_id: u8) {
    bytecode.push(ISA_OPCODE_NATIVE_CALL);
    bytecode.push(call_id);
}

fn emit_call_abs64(bytecode: &mut Vec<u8>, target: u64) {
    bytecode.push(ISA_OPCODE_CALL_ABS64);
    bytecode.extend_from_slice(&target.to_le_bytes());
}

fn emit_mmio_write64(bytecode: &mut Vec<u8>, guest_physical_address: u64, value: u64) {
    bytecode.push(ISA_OPCODE_MMIO_WRITE64);
    bytecode.extend_from_slice(&guest_physical_address.to_le_bytes());
    bytecode.extend_from_slice(&value.to_le_bytes());
}

#[cfg_attr(not(test), allow(dead_code))]
fn emit_mmio_read64(bytecode: &mut Vec<u8>, register: u8, guest_physical_address: u64) {
    bytecode.push(ISA_OPCODE_MMIO_READ64);
    bytecode.push(register);
    bytecode.extend_from_slice(&guest_physical_address.to_le_bytes());
}

fn emit_ret(bytecode: &mut Vec<u8>) {
    bytecode.push(ISA_OPCODE_RET);
}

fn emit_halt(bytecode: &mut Vec<u8>) {
    bytecode.push(ISA_OPCODE_HALT);
}

fn encode_guest_kernel_request(
    operation: u8,
    arg0_addr: u64,
    arg0_len: u64,
    arg1_addr: u64,
    arg1_len: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + 8 * 4);
    bytes.push(operation);
    bytes.extend_from_slice(&arg0_addr.to_le_bytes());
    bytes.extend_from_slice(&arg0_len.to_le_bytes());
    bytes.extend_from_slice(&arg1_addr.to_le_bytes());
    bytes.extend_from_slice(&arg1_len.to_le_bytes());
    bytes
}

fn read_guest_kernel_request(
    execution: &SoftVmExecutionCore,
    request_addr: u64,
) -> Result<(u8, u64, u64, u64, u64)> {
    let bytes = execution.guest_memory_slice(request_addr, 33);
    if bytes.len() != 33 {
        return Err(PlatformError::invalid(
            "guest kernel request must occupy exactly 33 bytes",
        ));
    }
    let operation = bytes[0];
    let arg0_addr = u64::from_le_bytes(bytes[1..9].try_into().unwrap_or([0; 8]));
    let arg0_len = u64::from_le_bytes(bytes[9..17].try_into().unwrap_or([0; 8]));
    let arg1_addr = u64::from_le_bytes(bytes[17..25].try_into().unwrap_or([0; 8]));
    let arg1_len = u64::from_le_bytes(bytes[25..33].try_into().unwrap_or([0; 8]));
    Ok((operation, arg0_addr, arg0_len, arg1_addr, arg1_len))
}

fn native_call_name(call_id: u8) -> &'static str {
    match call_id {
        NATIVE_CALL_FIRMWARE_DISPATCH => "firmware_dispatch",
        NATIVE_CALL_DIRECT_KERNEL_ENTRY => "direct_kernel_entry",
        NATIVE_CALL_INSTALL_MEDIA_PROBE => "install_media_probe",
        NATIVE_CALL_BOOT_DEVICE_TRANSFER => "boot_device_transfer",
        NATIVE_CALL_USERSPACE_CONTROL => "userspace_control",
        NATIVE_CALL_BOOT_SERVICE_ROUTE => "boot_service_route_dispatch",
        NATIVE_CALL_GUEST_UNAME => "guest_uname",
        NATIVE_CALL_GUEST_SYSTEM_STATE => "guest_system_state",
        NATIVE_CALL_GUEST_SYSTEMCTL_STATUS => "guest_systemctl_status",
        NATIVE_CALL_GUEST_CAT => "guest_cat",
        NATIVE_CALL_GUEST_ECHO_REDIRECT => "guest_echo_redirect",
        NATIVE_CALL_GUEST_TOUCH => "guest_touch",
        NATIVE_CALL_GUEST_LS => "guest_ls",
        NATIVE_CALL_GUEST_SHA256SUM => "guest_sha256sum",
        NATIVE_CALL_GUEST_UNIXBENCH => "guest_unixbench",
        NATIVE_CALL_GUEST_UNSUPPORTED => "guest_unsupported",
        NATIVE_CALL_GUEST_HTTP_FETCH => "guest_http_fetch",
        NATIVE_CALL_GUEST_TCP_CONNECT => "guest_tcp_connect",
        NATIVE_CALL_GUEST_DNS_LOOKUP => "guest_dns_lookup",
        NATIVE_CALL_GUEST_UDP_EXCHANGE => "guest_udp_exchange",
        NATIVE_CALL_GUEST_SERVICE_ROUTE => "guest_service_route_dispatch",
        _ => "unknown_native_call",
    }
}

fn guest_isa_register_name(register: u8) -> &'static str {
    match register {
        ISA_REGISTER_ARG0 => "r0",
        ISA_REGISTER_ARG1 => "r1",
        ISA_REGISTER_ARG2 => "r2",
        ISA_REGISTER_ARG3 => "r3",
        _ => "r?",
    }
}

fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        ISA_OPCODE_MOV_IMM64 => "mov_imm64",
        ISA_OPCODE_CALL_ABS64 => "call_abs64",
        ISA_OPCODE_RET => "ret",
        ISA_OPCODE_MMIO_WRITE64 => "mmio_write64",
        ISA_OPCODE_MMIO_READ64 => "mmio_read64",
        OPCODE_FIRMWARE_DISPATCH => "firmware_dispatch",
        OPCODE_DIRECT_KERNEL_ENTRY => "direct_kernel_entry",
        OPCODE_INSTALL_MEDIA_PROBE => "install_media_probe",
        OPCODE_BOOT_DEVICE_TRANSFER => "boot_device_transfer",
        OPCODE_USERSPACE_CONTROL => "userspace_control",
        OPCODE_BOOT_SERVICE_ROUTE => "boot_service_route_dispatch",
        OPCODE_GUEST_UNAME => "guest_uname",
        OPCODE_GUEST_SYSTEM_STATE => "guest_system_state",
        OPCODE_GUEST_SYSTEMCTL_STATUS => "guest_systemctl_status",
        OPCODE_GUEST_CAT => "guest_cat",
        OPCODE_GUEST_ECHO_REDIRECT => "guest_echo_redirect",
        OPCODE_GUEST_TOUCH => "guest_touch",
        OPCODE_GUEST_LS => "guest_ls",
        OPCODE_GUEST_SHA256SUM => "guest_sha256sum",
        OPCODE_GUEST_UNIXBENCH => "guest_unixbench",
        OPCODE_GUEST_UNSUPPORTED => "guest_unsupported",
        OPCODE_GUEST_HTTP_FETCH => "guest_http_fetch",
        OPCODE_GUEST_TCP_CONNECT => "guest_tcp_connect",
        OPCODE_GUEST_DNS_LOOKUP => "guest_dns_lookup",
        OPCODE_GUEST_UDP_EXCHANGE => "guest_udp_exchange",
        OPCODE_GUEST_SERVICE_ROUTE => "guest_service_route_dispatch",
        OPCODE_HALT => "halt",
        _ => "unknown",
    }
}

fn align_up_u64(value: u64, alignment: u64) -> u64 {
    if alignment <= 1 {
        return value;
    }
    let remainder = value % alignment;
    if remainder == 0 {
        value
    } else {
        value.saturating_add(alignment.saturating_sub(remainder))
    }
}

fn guest_page_index(guest_address: u64) -> u64 {
    guest_address / SOFT_VM_GUEST_PAGE_BYTES
}

fn guest_page_base(page_index: u64) -> u64 {
    page_index.saturating_mul(SOFT_VM_GUEST_PAGE_BYTES)
}

fn guest_pages_for_span(guest_address: u64, byte_len: u64) -> Vec<u64> {
    if byte_len == 0 {
        return Vec::new();
    }
    let start_page = guest_page_index(guest_address);
    let end_address = guest_address.saturating_add(byte_len.saturating_sub(1));
    let end_page = guest_page_index(end_address);
    (start_page..=end_page).collect()
}

fn splitmix64(value: u64) -> u64 {
    let mut z = value;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn normalize_guest_path(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid("guest path may not be empty"));
    }
    if !trimmed.starts_with('/') {
        return Err(PlatformError::invalid(
            "guest path must be absolute inside the native executor",
        ));
    }
    if trimmed.split('/').any(|segment| segment == "..") {
        return Err(PlatformError::invalid(
            "guest path may not contain parent traversal segments",
        ));
    }
    let segments = trimmed
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect::<Vec<_>>();
    Ok(if segments.is_empty() {
        String::from("/")
    } else {
        format!("/{}", segments.join("/"))
    })
}

fn strip_wrapping_quotes(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        let first = bytes[0];
        let last = bytes[trimmed.len().saturating_sub(1)];
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            return &trimmed[1..trimmed.len().saturating_sub(1)];
        }
    }
    trimmed
}

fn read_guest_file(
    execution: &SoftVmExecutionCore,
    control: &SoftVmGuestControl,
    path: &str,
) -> Option<String> {
    control
        .files
        .iter()
        .find(|file| file.path == path)
        .and_then(|file| {
            String::from_utf8(
                execution.guest_memory_slice(file.resident_guest_address, file.resident_byte_len),
            )
            .ok()
        })
}

fn file_allocation_label(path: &str) -> String {
    format!("file:{path}")
}

fn guest_path_token(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        String::from("_root")
    } else {
        trimmed.replace('/', "__")
    }
}

fn guest_directory_index_path(path: &str) -> String {
    format!("/run/guest-index/dir/{}.ls", guest_path_token(path))
}

fn guest_sha256_index_path(path: &str) -> String {
    format!("/run/guest-index/sha256/{}.txt", guest_path_token(path))
}

fn guest_parent_directories(path: &str) -> Vec<String> {
    let mut directories = vec![String::from("/")];
    let segments = path
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.len() <= 1 {
        return directories;
    }
    let mut current = String::new();
    for segment in segments.iter().take(segments.len().saturating_sub(1)) {
        current.push('/');
        current.push_str(segment);
        directories.push(current.clone());
    }
    directories
}

fn materialize_guest_file_projection(
    execution: &mut SoftVmExecutionCore,
    projection: GuestFileProjection,
) -> Result<SoftVmGuestFile> {
    let GuestFileProjection { path, contents } = projection;
    let allocation =
        execution.allocate_guest_data(file_allocation_label(&path), contents.as_bytes())?;
    Ok(SoftVmGuestFile {
        path,
        content_fingerprint: sha256_hex(contents.as_bytes()),
        resident_guest_address: allocation.guest_address,
        resident_byte_len: allocation.byte_len,
        contents,
    })
}

fn materialize_guest_file_projections(
    execution: &mut SoftVmExecutionCore,
    projections: impl IntoIterator<Item = GuestFileProjection>,
) -> Result<Vec<SoftVmGuestFile>> {
    projections
        .into_iter()
        .map(|projection| materialize_guest_file_projection(execution, projection))
        .collect()
}

fn guest_kernel_result_projections(
    operation: &str,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) -> [GuestFileProjection; 4] {
    [
        GuestFileProjection::new("/run/guest-kernel/operation", format!("{operation}\n")),
        GuestFileProjection::new("/run/guest-kernel/stdout", stdout),
        GuestFileProjection::new("/run/guest-kernel/stderr", stderr),
        GuestFileProjection::new("/run/guest-kernel/exit-code", format!("{exit_code}\n")),
    ]
}

fn initial_guest_kernel_file_projections() -> [GuestFileProjection; 4] {
    [
        GuestFileProjection::new("/run/guest-kernel/stdout", String::new()),
        GuestFileProjection::new("/run/guest-kernel/stderr", String::new()),
        GuestFileProjection::new("/run/guest-kernel/exit-code", String::from("0\n")),
        GuestFileProjection::new("/run/guest-kernel/operation", String::new()),
    ]
}

fn initial_guest_egress_file_projections() -> [GuestFileProjection; 9] {
    [
        GuestFileProjection::new(
            "/run/guest-egress/transport",
            format!("{GUEST_EGRESS_TRANSPORT}\n"),
        ),
        GuestFileProjection::new("/run/guest-egress/last-url", String::new()),
        GuestFileProjection::new("/run/guest-egress/last-method", String::new()),
        GuestFileProjection::new("/run/guest-egress/last-status-line", String::new()),
        GuestFileProjection::new("/run/guest-egress/last-content-type", String::new()),
        GuestFileProjection::new("/run/guest-egress/last-body-bytes", String::from("0\n")),
        GuestFileProjection::new("/run/guest-egress/last-truncated", String::from("false\n")),
        GuestFileProjection::new("/var/log/guest-egress/last-headers", String::new()),
        GuestFileProjection::new("/var/log/guest-egress/last-body", String::new()),
    ]
}

fn initial_guest_tcp_file_projections() -> [GuestFileProjection; 7] {
    [
        GuestFileProjection::new(
            "/run/guest-tcp/transport",
            format!("{GUEST_EGRESS_TRANSPORT}\n"),
        ),
        GuestFileProjection::new("/run/guest-tcp/last-target", String::new()),
        GuestFileProjection::new("/run/guest-tcp/last-probe", String::from("false\n")),
        GuestFileProjection::new("/run/guest-tcp/last-bytes-sent", String::from("0\n")),
        GuestFileProjection::new("/run/guest-tcp/last-bytes-received", String::from("0\n")),
        GuestFileProjection::new("/var/log/guest-tcp/last-sent", String::new()),
        GuestFileProjection::new("/var/log/guest-tcp/last-received", String::new()),
    ]
}

fn initial_guest_udp_file_projections() -> [GuestFileProjection; 7] {
    [
        GuestFileProjection::new(
            "/run/guest-udp/transport",
            format!("{GUEST_EGRESS_TRANSPORT}\n"),
        ),
        GuestFileProjection::new("/run/guest-udp/last-target", String::new()),
        GuestFileProjection::new("/run/guest-udp/last-probe", String::from("false\n")),
        GuestFileProjection::new("/run/guest-udp/last-bytes-sent", String::from("0\n")),
        GuestFileProjection::new("/run/guest-udp/last-bytes-received", String::from("0\n")),
        GuestFileProjection::new("/var/log/guest-udp/last-sent", String::new()),
        GuestFileProjection::new("/var/log/guest-udp/last-received", String::new()),
    ]
}

fn initial_guest_network_file_projections(hostname: &str) -> [GuestFileProjection; 7] {
    [
        GuestFileProjection::new("/run/guest-network/mode", format!("{GUEST_NETWORK_MODE}\n")),
        GuestFileProjection::new(
            "/run/guest-network/interface",
            format!("{GUEST_NETWORK_PRIMARY_INTERFACE}\n"),
        ),
        GuestFileProjection::new(
            "/run/guest-network/guest-ipv4",
            format!("{GUEST_NETWORK_GUEST_IPV4}\n"),
        ),
        GuestFileProjection::new(
            "/run/guest-network/guest-cidr",
            format!("{GUEST_NETWORK_GUEST_CIDR}\n"),
        ),
        GuestFileProjection::new(
            "/run/guest-network/gateway",
            format!("{GUEST_NETWORK_GATEWAY_IPV4}\n"),
        ),
        GuestFileProjection::new(
            "/run/guest-network/dns",
            format!("{GUEST_NETWORK_DNS_IPV4}\n"),
        ),
        GuestFileProjection::new(
            "/etc/resolv.conf",
            format!(
                "# UHost managed guest resolver for {hostname}\nnameserver {GUEST_NETWORK_DNS_IPV4}\nsearch uhost.internal\n"
            ),
        ),
    ]
}

fn initial_guest_ingress_file_projections(hostname: &str) -> Vec<GuestFileProjection> {
    vec![
        GuestFileProjection::new(
            "/run/guest-ingress/transport",
            format!("{GUEST_INGRESS_TRANSPORT}\n"),
        ),
        GuestFileProjection::new(
            "/run/guest-ingress/web-root",
            format!("{GUEST_INGRESS_WEB_ROOT}\n"),
        ),
        GuestFileProjection::new("/run/guest-ingress/default-route", String::from("/\n")),
        GuestFileProjection::new(
            "/run/guest-ingress/tcp/default-service",
            format!("{GUEST_INGRESS_TCP_DEFAULT_SERVICE}\n"),
        ),
        GuestFileProjection::new(
            format!("/run/guest-ingress/tcp/services/{GUEST_INGRESS_TCP_DEFAULT_SERVICE}/bind"),
            format!("{GUEST_INGRESS_DEFAULT_HOST_BIND}\n"),
        ),
        GuestFileProjection::new(
            format!("/run/guest-ingress/tcp/services/{GUEST_INGRESS_TCP_DEFAULT_SERVICE}/mode"),
            String::from("echo\n"),
        ),
        GuestFileProjection::new(
            format!("/run/guest-ingress/tcp/services/{GUEST_INGRESS_TCP_DEFAULT_SERVICE}/banner"),
            String::from("UHost managed TCP ingress ready\n"),
        ),
        GuestFileProjection::new(
            format!("/run/guest-ingress/tcp/services/{GUEST_INGRESS_TCP_DEFAULT_SERVICE}/response"),
            String::new(),
        ),
        GuestFileProjection::new(
            "/run/guest-ingress/udp/default-service",
            format!("{GUEST_INGRESS_UDP_DEFAULT_SERVICE}\n"),
        ),
        GuestFileProjection::new(
            format!("/run/guest-ingress/udp/services/{GUEST_INGRESS_UDP_DEFAULT_SERVICE}/bind"),
            format!("{GUEST_INGRESS_DEFAULT_HOST_BIND}\n"),
        ),
        GuestFileProjection::new(
            format!("/run/guest-ingress/udp/services/{GUEST_INGRESS_UDP_DEFAULT_SERVICE}/mode"),
            String::from("echo\n"),
        ),
        GuestFileProjection::new(
            format!("/run/guest-ingress/udp/services/{GUEST_INGRESS_UDP_DEFAULT_SERVICE}/response"),
            String::new(),
        ),
        GuestFileProjection::new(
            format!("{GUEST_INGRESS_WEB_ROOT}/index.html"),
            format!(
                concat!(
                    "<!doctype html>\n",
                    "<html lang=\"en\">\n",
                    "<head>\n",
                    "  <meta charset=\"utf-8\">\n",
                    "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
                    "  <title>UHost Managed UVM</title>\n",
                    "  <style>\n",
                    "    :root {{ color-scheme: dark; }}\n",
                    "    body {{ margin: 0; font: 16px/1.5 ui-sans-serif, system-ui, sans-serif; background: #0b1220; color: #e5eefb; }}\n",
                    "    main {{ max-width: 56rem; margin: 0 auto; padding: 4rem 1.5rem; }}\n",
                    "    .eyebrow {{ letter-spacing: 0.16em; text-transform: uppercase; color: #7dd3fc; font-size: 0.78rem; }}\n",
                    "    h1 {{ margin: 0.75rem 0 1rem; font-size: clamp(2.25rem, 5vw, 4rem); line-height: 1.05; }}\n",
                    "    p {{ max-width: 42rem; color: #bfd3ea; }}\n",
                    "    code {{ background: rgba(148, 163, 184, 0.14); padding: 0.15rem 0.45rem; border-radius: 999px; }}\n",
                    "  </style>\n",
                    "</head>\n",
                    "<body>\n",
                    "<main>\n",
                    "  <div class=\"eyebrow\">UHost Managed UVM</div>\n",
                    "  <h1>Managed ingress is live.</h1>\n",
                    "  <p>This guest is serving HTTP from <code>{web_root}</code> on <code>{hostname}</code>. Update files under <code>{web_root}</code> through guest control and the managed ingress mirror will publish them.</p>\n",
                    "</main>\n",
                    "</body>\n",
                    "</html>\n"
                ),
                web_root = GUEST_INGRESS_WEB_ROOT,
                hostname = hostname,
            ),
        ),
        GuestFileProjection::new(
            format!("{GUEST_INGRESS_WEB_ROOT}/healthz"),
            String::from("ok\n"),
        ),
    ]
}

fn guest_egress_result_projections(response: &GuestEgressResponse) -> [GuestFileProjection; 8] {
    [
        GuestFileProjection::new("/run/guest-egress/last-url", format!("{}\n", response.url)),
        GuestFileProjection::new(
            "/run/guest-egress/last-method",
            format!("{}\n", response.method.as_str()),
        ),
        GuestFileProjection::new(
            "/run/guest-egress/last-status-line",
            format!("{}\n", response.status_line),
        ),
        GuestFileProjection::new(
            "/run/guest-egress/last-content-type",
            format!("{}\n", response.content_type),
        ),
        GuestFileProjection::new(
            "/run/guest-egress/last-body-bytes",
            format!("{}\n", response.body_bytes),
        ),
        GuestFileProjection::new(
            "/run/guest-egress/last-truncated",
            if response.truncated {
                String::from("true\n")
            } else {
                String::from("false\n")
            },
        ),
        GuestFileProjection::new(
            "/var/log/guest-egress/last-headers",
            response.headers_text.clone(),
        ),
        GuestFileProjection::new(
            "/var/log/guest-egress/last-body",
            response.body_text.clone(),
        ),
    ]
}

fn guest_tcp_result_projections(response: &GuestTcpConnectResponse) -> [GuestFileProjection; 7] {
    [
        GuestFileProjection::new(
            "/run/guest-tcp/last-target",
            format!("{}\n", response.target),
        ),
        GuestFileProjection::new(
            "/run/guest-tcp/last-probe",
            if response.probe_only {
                String::from("true\n")
            } else {
                String::from("false\n")
            },
        ),
        GuestFileProjection::new(
            "/run/guest-tcp/last-bytes-sent",
            format!("{}\n", response.bytes_sent),
        ),
        GuestFileProjection::new(
            "/run/guest-tcp/last-bytes-received",
            format!("{}\n", response.bytes_received),
        ),
        GuestFileProjection::new(
            "/var/log/guest-tcp/last-sent",
            response.payload_text.clone(),
        ),
        GuestFileProjection::new("/var/log/guest-tcp/last-received", response.stdout.clone()),
        GuestFileProjection::new(
            "/run/guest-tcp/transport",
            format!("{GUEST_EGRESS_TRANSPORT}\n"),
        ),
    ]
}

fn guest_udp_result_projections(response: &GuestUdpExchangeResponse) -> [GuestFileProjection; 7] {
    [
        GuestFileProjection::new(
            "/run/guest-udp/last-target",
            format!("{}\n", response.target),
        ),
        GuestFileProjection::new(
            "/run/guest-udp/last-probe",
            if response.probe_only {
                String::from("true\n")
            } else {
                String::from("false\n")
            },
        ),
        GuestFileProjection::new(
            "/run/guest-udp/last-bytes-sent",
            format!("{}\n", response.bytes_sent),
        ),
        GuestFileProjection::new(
            "/run/guest-udp/last-bytes-received",
            format!("{}\n", response.bytes_received),
        ),
        GuestFileProjection::new(
            "/var/log/guest-udp/last-sent",
            response.payload_text.clone(),
        ),
        GuestFileProjection::new("/var/log/guest-udp/last-received", response.stdout.clone()),
        GuestFileProjection::new(
            "/run/guest-udp/transport",
            format!("{GUEST_EGRESS_TRANSPORT}\n"),
        ),
    ]
}

fn unixbench_metric_projections(metrics: &NativeUnixBenchMetrics) -> Vec<GuestFileProjection> {
    let redacted_source_path = metrics
        .source_path
        .as_ref()
        .and_then(|path| path.file_name())
        .map(|name| format!("{}\n", name.to_string_lossy()))
        .unwrap_or_default();
    let mut projections = vec![
        GuestFileProjection::new(
            "/var/lib/unixbench/metrics/dhrystone",
            format!("{:.1}\n", metrics.dhrystone),
        ),
        GuestFileProjection::new(
            "/var/lib/unixbench/metrics/whetstone",
            format!("{:.1}\n", metrics.whetstone),
        ),
        GuestFileProjection::new(
            "/var/lib/unixbench/metrics/execl",
            format!("{:.1}\n", metrics.execl),
        ),
        GuestFileProjection::new(
            "/var/lib/unixbench/metrics/copy",
            format!("{:.1}\n", metrics.copy),
        ),
        GuestFileProjection::new(
            "/var/lib/unixbench/metrics/index",
            format!("{:.1}\n", metrics.index),
        ),
        GuestFileProjection::new(
            "/var/lib/unixbench/metrics/source",
            format!("{}\n", metrics.source_kind.as_str()),
        ),
    ];
    projections.push(GuestFileProjection::new(
        "/var/lib/unixbench/metrics/source_path",
        redacted_source_path,
    ));
    projections
}

fn unixbench_artifact_projections(
    run_id: u32,
    score: f64,
    summary: &str,
) -> [GuestFileProjection; 3] {
    [
        GuestFileProjection::new("/var/log/unixbench/latest.log", summary),
        GuestFileProjection::new(format!("/var/log/unixbench/run-{run_id:04}.log"), summary),
        GuestFileProjection::new("/var/tmp/unixbench-score", format!("{score:.1}\n")),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestIngressServiceDefinition {
    service_name: String,
    bind: String,
    mode: String,
}

fn guest_file_contents<'a>(files: &'a [SoftVmGuestFile], path: &str) -> Option<&'a str> {
    files
        .iter()
        .find(|file| file.path == path)
        .map(|file| file.contents.as_str())
}

fn configured_guest_ingress_services(
    files: &[SoftVmGuestFile],
    protocol: &str,
    default_service: &str,
) -> Vec<GuestIngressServiceDefinition> {
    let services_root = format!("/run/guest-ingress/{protocol}/services/");
    let default_service_path = format!("/run/guest-ingress/{protocol}/default-service");
    let mut service_names = BTreeSet::new();
    let default_name = guest_file_contents(files, default_service_path.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_service);
    let _ = service_names.insert(default_name.to_owned());
    for file in files {
        let Some(remainder) = file.path.strip_prefix(&services_root) else {
            continue;
        };
        let Some((service_name, _)) = remainder.split_once('/') else {
            continue;
        };
        if !service_name.is_empty() {
            let _ = service_names.insert(service_name.to_owned());
        }
    }
    service_names
        .into_iter()
        .map(|service_name| {
            let service_root = format!("{services_root}{service_name}");
            let bind = guest_file_contents(files, format!("{service_root}/bind").as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(GUEST_INGRESS_DEFAULT_HOST_BIND)
                .to_owned();
            let mode = guest_file_contents(files, format!("{service_root}/mode").as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("echo")
                .to_owned();
            GuestIngressServiceDefinition {
                service_name,
                bind,
                mode,
            }
        })
        .collect::<Vec<_>>()
}

fn render_guest_ip_addr_report() -> String {
    format!(
        concat!(
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default\n",
            "    inet 127.0.0.1/8 scope host lo\n",
            "2: {iface}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default\n",
            "    inet {guest_cidr} brd 10.0.2.255 scope global dynamic {iface}\n",
        ),
        iface = GUEST_NETWORK_PRIMARY_INTERFACE,
        guest_cidr = GUEST_NETWORK_GUEST_CIDR,
    )
}

fn render_guest_ip_route_report() -> String {
    format!(
        concat!(
            "default via {gateway} dev {iface}\n",
            "10.0.2.0/24 dev {iface} proto kernel scope link src {guest_ipv4}\n",
        ),
        gateway = GUEST_NETWORK_GATEWAY_IPV4,
        iface = GUEST_NETWORK_PRIMARY_INTERFACE,
        guest_ipv4 = GUEST_NETWORK_GUEST_IPV4,
    )
}

fn render_guest_proc_net_dev() -> String {
    String::from(concat!(
        "Inter-|   Receive                                                |  Transmit\n",
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
        "    lo:       0       0    0    0    0     0          0         0       0       0    0    0    0     0       0          0\n",
        "  eth0:       0       0    0    0    0     0          0         0       0       0    0    0    0     0       0          0\n",
    ))
}

fn render_guest_proc_net_route() -> String {
    format!(
        concat!(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
            "{iface}\t00000000\t0202000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
            "{iface}\t0002000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
        ),
        iface = GUEST_NETWORK_PRIMARY_INTERFACE,
    )
}

fn render_guest_resolvectl_status(hostname: &str) -> String {
    format!(
        concat!(
            "Global\n",
            "       Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported\n",
            "resolv.conf mode: synthetic\n\n",
            "Link 2 ({iface})\n",
            "    Current Scopes: DNS\n",
            "         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported\n",
            "Current DNS Server: {dns}\n",
            "       DNS Servers: {dns}\n",
            "        DNS Domain: uhost.internal\n",
            "          Hostname: {hostname}\n",
        ),
        iface = GUEST_NETWORK_PRIMARY_INTERFACE,
        dns = GUEST_NETWORK_DNS_IPV4,
        hostname = hostname,
    )
}

fn render_guest_socket_summary(
    transport: &str,
    services: &[GuestIngressServiceDefinition],
) -> String {
    let header = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n";
    if services.is_empty() {
        return String::from(header);
    }
    let mut rendered = String::from(header);
    for service in services {
        let state = if transport == "tcp" {
            "LISTEN"
        } else {
            "UNCONN"
        };
        rendered.push_str(&format!(
            "{state:<6} 0      128    {:<18} 0.0.0.0:* users:((\"{}\",pid=1,mode={}))\n",
            service.bind, service.service_name, service.mode
        ));
    }
    rendered
}

fn render_guest_port_forward_inventory(
    transport: &str,
    services: &[GuestIngressServiceDefinition],
) -> String {
    if services.is_empty() {
        return String::new();
    }
    services
        .iter()
        .map(|service| {
            format!(
                "{transport}:{name}:{bind}:{mode}\n",
                name = service.service_name,
                bind = service.bind,
                mode = service.mode,
            )
        })
        .collect::<String>()
}

fn refresh_guest_network_views(
    execution: &mut SoftVmExecutionCore,
    files: &mut Vec<SoftVmGuestFile>,
    hostname: &str,
) -> Result<()> {
    let tcp_services =
        configured_guest_ingress_services(files, "tcp", GUEST_INGRESS_TCP_DEFAULT_SERVICE);
    let udp_services =
        configured_guest_ingress_services(files, "udp", GUEST_INGRESS_UDP_DEFAULT_SERVICE);
    upsert_guest_file_batch(
        execution,
        files,
        [
            GuestFileProjection::new("/run/guest-network/ip-addr", render_guest_ip_addr_report()),
            GuestFileProjection::new(
                "/run/guest-network/ip-route",
                render_guest_ip_route_report(),
            ),
            GuestFileProjection::new(
                "/run/guest-network/hostname-i",
                format!("{GUEST_NETWORK_GUEST_IPV4}\n"),
            ),
            GuestFileProjection::new(
                "/run/guest-network/resolvectl-status",
                render_guest_resolvectl_status(hostname),
            ),
            GuestFileProjection::new("/proc/net/dev", render_guest_proc_net_dev()),
            GuestFileProjection::new("/proc/net/route", render_guest_proc_net_route()),
            GuestFileProjection::new(
                "/run/guest-network/ss-ltn",
                render_guest_socket_summary("tcp", &tcp_services),
            ),
            GuestFileProjection::new(
                "/run/guest-network/ss-lun",
                render_guest_socket_summary("udp", &udp_services),
            ),
            GuestFileProjection::new(
                "/run/guest-network/port-forwards/tcp",
                render_guest_port_forward_inventory("tcp", &tcp_services),
            ),
            GuestFileProjection::new(
                "/run/guest-network/port-forwards/udp",
                render_guest_port_forward_inventory("udp", &udp_services),
            ),
        ],
    )
}

fn guest_control_services(spec: &SoftVmRuntimeSpec) -> Vec<SoftVmGuestService> {
    let mut services = vec![
        SoftVmGuestService {
            name: String::from("init"),
            state: String::from("running"),
        },
        SoftVmGuestService {
            name: String::from("usernet"),
            state: String::from("running"),
        },
        SoftVmGuestService {
            name: String::from("guest-control"),
            state: String::from("running"),
        },
        SoftVmGuestService {
            name: String::from("egress-relay"),
            state: String::from("running"),
        },
        SoftVmGuestService {
            name: String::from("tcp-egress-relay"),
            state: String::from("running"),
        },
        SoftVmGuestService {
            name: String::from("udp-egress-relay"),
            state: String::from("running"),
        },
        SoftVmGuestService {
            name: String::from("dns-relay"),
            state: String::from("running"),
        },
        SoftVmGuestService {
            name: String::from("ingress-relay"),
            state: String::from("running"),
        },
        SoftVmGuestService {
            name: String::from("tcp-ingress-relay"),
            state: String::from("running"),
        },
        SoftVmGuestService {
            name: String::from("udp-ingress-relay"),
            state: String::from("running"),
        },
    ];
    services.push(SoftVmGuestService {
        name: if spec.machine.boot.cdrom_image.is_some() {
            String::from("installer")
        } else {
            String::from("cloud-init")
        },
        state: String::from("running"),
    });
    services
}

fn guest_command_channel_last_result(
    history: &[SoftVmGuestCommandResult],
    channel: SoftVmGuestCommandChannel,
) -> Option<&SoftVmGuestCommandResult> {
    history
        .iter()
        .rev()
        .find(|result| result.channel == channel.as_str())
}

fn guest_command_channel_counts(
    execution: &SoftVmExecutionCore,
    history: &[SoftVmGuestCommandResult],
    channel: SoftVmGuestCommandChannel,
) -> (u64, u64) {
    match channel.device_loop_name() {
        Some(device_loop_name) => execution
            .device_loop_by_name(device_loop_name)
            .map(|device_loop| {
                (
                    device_loop.register("guest_command_tx_count"),
                    device_loop.register("guest_command_rx_count"),
                )
            })
            .unwrap_or((0, 0)),
        None => {
            let count = saturating_u64_len(
                history
                    .iter()
                    .filter(|result| result.channel == channel.as_str())
                    .count(),
            );
            (count, count)
        }
    }
}

fn guest_command_channel_transport_ready(
    execution: &SoftVmExecutionCore,
    channel: SoftVmGuestCommandChannel,
) -> bool {
    channel
        .device_loop_name()
        .is_none_or(|device_loop_name| execution.device_loop_by_name(device_loop_name).is_some())
}

fn guest_command_channel_state(
    execution: &SoftVmExecutionCore,
    history: &[SoftVmGuestCommandResult],
    channel: SoftVmGuestCommandChannel,
) -> SoftVmGuestCommandChannelState {
    let (tx_count, rx_count) = guest_command_channel_counts(execution, history, channel);
    let last_result = guest_command_channel_last_result(history, channel);
    SoftVmGuestCommandChannelState {
        name: String::from(channel.as_str()),
        delivery_path: String::from(channel.delivery_path()),
        state: if guest_command_channel_transport_ready(execution, channel) {
            String::from("ready")
        } else {
            String::from("unavailable")
        },
        tx_count,
        rx_count,
        last_command: last_result.map(|result| result.command.clone()),
        last_exit_code: last_result.map(|result| result.exit_code),
    }
}

fn guest_command_channel_states(
    execution: &SoftVmExecutionCore,
    history: &[SoftVmGuestCommandResult],
) -> Vec<SoftVmGuestCommandChannelState> {
    [
        SoftVmGuestCommandChannel::Serial,
        SoftVmGuestCommandChannel::VirtioConsole,
        SoftVmGuestCommandChannel::GuestAgent,
    ]
    .into_iter()
    .map(|channel| guest_command_channel_state(execution, history, channel))
    .collect()
}

fn sync_guest_command_channel_views(
    execution: &SoftVmExecutionCore,
    control: &mut SoftVmGuestControl,
) {
    control.channels = guest_command_channel_states(execution, &control.history);
}

fn ensure_guest_command_channel_ready(
    execution: &SoftVmExecutionCore,
    history: &[SoftVmGuestCommandResult],
    channel: SoftVmGuestCommandChannel,
) -> Result<()> {
    let state = guest_command_channel_state(execution, history, channel);
    if state.state != "ready" {
        return Err(PlatformError::conflict(format!(
            "guest command channel `{}` is unavailable for this machine contract",
            channel.as_str()
        )));
    }
    Ok(())
}

fn record_guest_command_channel_dispatch(
    execution: &mut SoftVmExecutionCore,
    channel: SoftVmGuestCommandChannel,
    command: &str,
) -> Result<()> {
    let token = u64::try_from(command.len()).unwrap_or(u64::MAX);
    match channel {
        SoftVmGuestCommandChannel::Serial => {
            let _ = execution.dispatch_mmio_write(
                UART_CONSOLE_MMIO_BASE,
                token,
                Some(format!("serial guest command dispatched `{command}`")),
            )?;
            if let Some(device_loop) = execution.device_loop_mut_by_name("uart_console") {
                device_loop.set_register(
                    "guest_command_tx_count",
                    device_loop
                        .register("guest_command_tx_count")
                        .saturating_add(1),
                );
            }
        }
        SoftVmGuestCommandChannel::VirtioConsole => {
            let _ = execution.dispatch_mmio_write(
                VIRTIO_CONSOLE_MMIO_BASE,
                token,
                Some(format!(
                    "virtio-console guest command dispatched `{command}`"
                )),
            )?;
            if let Some(device_loop) = execution.device_loop_mut_by_name("virtio_console") {
                device_loop.set_register(
                    "guest_command_tx_count",
                    device_loop
                        .register("guest_command_tx_count")
                        .saturating_add(1),
                );
            }
        }
        SoftVmGuestCommandChannel::GuestAgent => {
            execution.completed_events.push(SoftVmExecutionEvent::new(
                "guest_agent_dispatch",
                format!("guest-agent dispatched `{command}`"),
            ))
        }
    }
    execution.completed_events.push(SoftVmExecutionEvent::new(
        "guest_command_channel_dispatch",
        format!("{} command path accepted `{command}`", channel.as_str()),
    ));
    Ok(())
}

fn record_guest_command_channel_completion(
    execution: &mut SoftVmExecutionCore,
    result: &SoftVmGuestCommandResult,
) -> Result<()> {
    let channel = SoftVmGuestCommandChannel::parse(result.channel.as_str())?;

    let response_bytes =
        u64::try_from(result.stdout.len().saturating_add(result.stderr.len())).unwrap_or(u64::MAX);
    let detail = format!(
        "{} guest command completed `{}` with exit code {}",
        channel.as_str(),
        result.command,
        result.exit_code
    );
    match channel {
        SoftVmGuestCommandChannel::Serial => {
            if let Some(device_loop) = execution.device_loop_mut_by_name("uart_console")
                && let Some(queue) = device_loop.queue_mut("rx")
            {
                queue.pending.push(response_bytes);
            }
            let _ = execution.dispatch_mmio_read(UART_CONSOLE_MMIO_BASE)?;
            if let Some(device_loop) = execution.device_loop_mut_by_name("uart_console") {
                device_loop.set_register(
                    "guest_command_rx_count",
                    device_loop
                        .register("guest_command_rx_count")
                        .saturating_add(1),
                );
            }
            execution.completed_events.push(SoftVmExecutionEvent::new(
                "guest_command_channel_completion",
                detail,
            ));
        }
        SoftVmGuestCommandChannel::VirtioConsole => {
            let _ = execution.dispatch_mmio_read(VIRTIO_CONSOLE_MMIO_BASE)?;
            if let Some(device_loop) = execution.device_loop_mut_by_name("virtio_console") {
                device_loop.set_register(
                    "guest_command_rx_count",
                    device_loop
                        .register("guest_command_rx_count")
                        .saturating_add(1),
                );
            }
            execution.completed_events.push(SoftVmExecutionEvent::new(
                "guest_command_channel_completion",
                detail,
            ));
        }
        SoftVmGuestCommandChannel::GuestAgent => {
            execution.completed_events.push(SoftVmExecutionEvent::new(
                "guest_agent_completion",
                detail.clone(),
            ));
            execution.completed_events.push(SoftVmExecutionEvent::new(
                "guest_command_channel_completion",
                detail,
            ));
        }
    }
    Ok(())
}

fn guest_service_status_projection(service: &SoftVmGuestService) -> GuestFileProjection {
    GuestFileProjection::new(
        format!("/run/systemd/services/{}.status", service.name),
        format!(
            "● {}.service - UVM native synthetic service\n   Loaded: loaded (/native/{}.service; enabled)\n   Active: {}\n",
            service.name, service.name, service.state
        ),
    )
}

fn direct_kernel_guest_control_projections(
    execution: &SoftVmExecutionCore,
    state: &SoftVmDirectKernelBootState,
) -> Vec<GuestFileProjection> {
    let boot_params = String::from_utf8_lossy(
        &execution.guest_memory_slice(state.boot_params_guest_address, state.boot_params_byte_len),
    )
    .into_owned();
    vec![
        GuestFileProjection::new("/run/uhost/direct-kernel/boot-params", boot_params),
        GuestFileProjection::new(
            "/run/uhost/direct-kernel/handoff",
            format!(
                concat!(
                    "kernel_entry=0x{:x}\n",
                    "kernel_bytes={}\n",
                    "kernel_preview_bytes={}\n",
                    "boot_params_addr=0x{:x}\n",
                    "cmdline_addr=0x{:x}\n",
                    "cmdline_len={}\n",
                ),
                state.kernel_entry_guest_address,
                state.kernel_byte_len,
                state.preview_byte_len,
                state.boot_params_guest_address,
                state.command_line_guest_address,
                state.command_line_byte_len,
            ),
        ),
    ]
}

fn guest_control_file_projections(
    spec: &SoftVmRuntimeSpec,
    guest_memory_bytes: u64,
    hostname: &str,
    ready_marker_path: &str,
    boot_witness: Option<&SoftVmBootWitness>,
    direct_kernel_projections: &[GuestFileProjection],
    services: &[SoftVmGuestService],
) -> Vec<GuestFileProjection> {
    let unixbench_metrics = native_unixbench_metrics(spec.machine.vcpu, guest_memory_bytes);
    let mut projections = vec![
        GuestFileProjection::new("/etc/hostname", format!("{hostname}\n")),
        GuestFileProjection::new(ready_marker_path, String::from("true\n")),
        GuestFileProjection::new(
            "/etc/os-release",
            format!(
                "NAME=\"UVM Native Guest\"\nPRETTY_NAME=\"UVM Native Guest ({})\"\n",
                spec.machine.boot.firmware_profile
            ),
        ),
        GuestFileProjection::new(
            "/proc/sys/kernel/uname",
            format!(
                "Linux {hostname} 0.1.0 #1 UVM PREEMPT_SOFT {} GNU/Linux\n",
                spec.machine.guest_architecture
            ),
        ),
        GuestFileProjection::new("/proc/meminfo", native_meminfo_report(guest_memory_bytes)),
        GuestFileProjection::new("/run/system-state", String::from("running\n")),
    ];
    projections.extend(unixbench_metric_projections(&unixbench_metrics));
    projections.extend(initial_guest_kernel_file_projections());
    projections.extend(initial_guest_network_file_projections(hostname));
    projections.extend(initial_guest_egress_file_projections());
    projections.extend(initial_guest_tcp_file_projections());
    projections.extend(initial_guest_udp_file_projections());
    projections.extend(initial_guest_ingress_file_projections(hostname));
    if direct_kernel_boot(spec) {
        projections.push(GuestFileProjection::new(
            "/proc/cmdline",
            format!("{}\n", direct_kernel_command_line(spec)),
        ));
        projections.push(GuestFileProjection::new(
            "/run/uhost/direct-kernel/kernel",
            format!(
                "{}\n",
                boot_artifact_display_name(spec.firmware_artifact_source())
            ),
        ));
        projections.extend(direct_kernel_projections.iter().cloned());
    }
    if let Some(witness) = boot_witness {
        projections.push(GuestFileProjection::new(
            "/var/log/boot.log",
            format!("{}\n", witness.console_trace.join("\n")),
        ));
        projections.push(GuestFileProjection::new(
            "/run/uhost/secure-boot/state",
            if witness.secure_boot_enabled {
                String::from("enabled\n")
            } else {
                String::from("disabled\n")
            },
        ));
        if witness.secure_boot_enabled {
            projections.push(GuestFileProjection::new(
                "/run/uhost/secure-boot/measurements",
                format!("{}\n", witness.secure_boot_measurements.join("\n")),
            ));
        }
    }
    projections.extend(services.iter().map(guest_service_status_projection));
    projections
}

fn upsert_guest_file_raw(
    execution: &mut SoftVmExecutionCore,
    files: &mut Vec<SoftVmGuestFile>,
    path: String,
    contents: String,
) -> Result<()> {
    let allocation =
        execution.allocate_guest_data(file_allocation_label(&path), contents.as_bytes())?;
    if let Some(file) = files.iter_mut().find(|file| file.path == path) {
        file.contents = contents.clone();
        file.content_fingerprint = sha256_hex(contents.as_bytes());
        file.resident_guest_address = allocation.guest_address;
        file.resident_byte_len = allocation.byte_len;
    } else {
        files.push(SoftVmGuestFile {
            path,
            content_fingerprint: sha256_hex(contents.as_bytes()),
            resident_guest_address: allocation.guest_address,
            resident_byte_len: allocation.byte_len,
            contents,
        });
        files.sort_by(|left, right| left.path.cmp(&right.path));
    }
    Ok(())
}

fn refresh_guest_metadata_batch(
    execution: &mut SoftVmExecutionCore,
    files: &mut Vec<SoftVmGuestFile>,
    paths: impl IntoIterator<Item = String>,
) -> Result<()> {
    let paths = paths.into_iter().collect::<BTreeSet<_>>();
    if paths.is_empty() {
        return Ok(());
    }
    let mut directories = BTreeSet::new();
    for path in &paths {
        if let Some(contents) = files
            .iter()
            .find(|file| file.path == *path)
            .map(|file| file.contents.clone())
        {
            upsert_guest_file_raw(
                execution,
                files,
                guest_sha256_index_path(path),
                format!("{}  {path}\n", sha256_hex(contents.as_bytes())),
            )?;
            upsert_guest_file_raw(
                execution,
                files,
                guest_directory_index_path(path),
                format!("{}\n", guest_basename(path)),
            )?;
        }
        directories.extend(guest_parent_directories(path));
    }
    for directory in directories {
        let entries = list_guest_entries_in_files(files, &directory);
        let listing = if entries.is_empty() {
            String::new()
        } else {
            format!("{}\n", entries.join("\n"))
        };
        upsert_guest_file_raw(
            execution,
            files,
            guest_directory_index_path(&directory),
            listing,
        )?;
    }
    Ok(())
}

fn upsert_guest_file_batch(
    execution: &mut SoftVmExecutionCore,
    files: &mut Vec<SoftVmGuestFile>,
    projections: impl IntoIterator<Item = GuestFileProjection>,
) -> Result<()> {
    let mut affected_paths = BTreeSet::new();
    for projection in projections {
        let GuestFileProjection { path, contents } = projection;
        let _ = affected_paths.insert(path.clone());
        upsert_guest_file_raw(execution, files, path, contents)?;
    }
    refresh_guest_metadata_batch(execution, files, affected_paths)
}

fn upsert_guest_file(
    execution: &mut SoftVmExecutionCore,
    files: &mut Vec<SoftVmGuestFile>,
    path: String,
    contents: String,
) -> Result<()> {
    upsert_guest_file_batch(execution, files, [GuestFileProjection::new(path, contents)])
}

fn write_guest_kernel_files(
    execution: &mut SoftVmExecutionCore,
    files: &mut Vec<SoftVmGuestFile>,
    operation: &str,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) -> Result<()> {
    upsert_guest_file_batch(
        execution,
        files,
        guest_kernel_result_projections(operation, exit_code, stdout, stderr),
    )
}

fn guest_basename(path: &str) -> &str {
    path.rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or("/")
}

fn list_guest_entries_in_files(files: &[SoftVmGuestFile], path: &str) -> Vec<String> {
    if let Some(file) = files.iter().find(|file| file.path == path) {
        return vec![String::from(guest_basename(&file.path))];
    }
    let prefix = if path == "/" {
        String::from("/")
    } else {
        format!("{path}/")
    };
    let mut entries = BTreeSet::new();
    for file in files {
        if let Some(remainder) = file.path.strip_prefix(&prefix)
            && let Some(entry) = remainder.split('/').next()
            && !entry.is_empty()
        {
            let _ = entries.insert(String::from(entry));
        }
    }
    entries.into_iter().collect::<Vec<_>>()
}

fn normalize_guest_command(value: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("guest command may not be empty"));
    }
    if normalized.len() > 512 {
        return Err(PlatformError::invalid("guest command exceeds 512 bytes"));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "guest command may not contain control characters",
        ));
    }
    Ok(normalized.to_owned())
}

fn parse_guest_command_request(value: &str) -> Result<(SoftVmGuestCommandChannel, String)> {
    let trimmed = value.trim();
    if let Some((channel, remainder)) = trimmed.split_once("::")
        && !channel.chars().any(char::is_whitespace)
        && let Ok(channel) = SoftVmGuestCommandChannel::parse(channel)
    {
        return Ok((channel, normalize_guest_command(remainder)?));
    }
    Ok((
        SoftVmGuestCommandChannel::Serial,
        normalize_guest_command(trimmed)?,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuestEgressMethod {
    Get,
    Head,
}

impl GuestEgressMethod {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "GET" => Ok(Self::Get),
            "HEAD" => Ok(Self::Head),
            _ => Err(PlatformError::invalid(
                "guest egress method must be GET or HEAD",
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestEgressRequest {
    method: GuestEgressMethod,
    url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuestEgressScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestEgressTarget {
    scheme: GuestEgressScheme,
    url: String,
    authority: String,
    host: String,
    port: u16,
    path_and_query: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestEgressResponse {
    url: String,
    method: GuestEgressMethod,
    http_status: u16,
    status_line: String,
    headers_text: String,
    body_text: String,
    content_type: String,
    body_bytes: usize,
    truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedHttpHeaderBlock {
    status_line: String,
    http_status: u16,
    headers: Vec<(String, String)>,
    normalized_header_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestEgressFailure {
    exit_code: i32,
    stderr: String,
}

impl GuestEgressFailure {
    fn new(exit_code: i32, message: impl Into<String>) -> Self {
        let mut stderr = message.into();
        if !stderr.ends_with('\n') {
            stderr.push('\n');
        }
        Self { exit_code, stderr }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestTcpConnectRequest {
    host: String,
    port: u16,
    payload: Option<String>,
    probe_only: bool,
}

impl GuestTcpConnectRequest {
    fn target(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    fn wire_mode(&self) -> String {
        if self.probe_only {
            String::from("probe")
        } else if let Some(payload) = self.payload.as_deref() {
            format!("exchange\n{payload}")
        } else {
            String::from("exchange")
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestTcpConnectResponse {
    target: String,
    probe_only: bool,
    bytes_sent: usize,
    bytes_received: usize,
    payload_text: String,
    stdout: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestTcpFailure {
    exit_code: i32,
    stderr: String,
}

impl GuestTcpFailure {
    fn new(exit_code: i32, message: impl Into<String>) -> Self {
        let mut stderr = message.into();
        if !stderr.ends_with('\n') {
            stderr.push('\n');
        }
        Self { exit_code, stderr }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestUdpExchangeRequest {
    host: String,
    port: u16,
    payload: Option<String>,
    probe_only: bool,
}

impl GuestUdpExchangeRequest {
    fn target(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    fn wire_mode(&self) -> String {
        if self.probe_only {
            String::from("probe")
        } else if let Some(payload) = self.payload.as_deref() {
            format!("exchange\n{payload}")
        } else {
            String::from("exchange")
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestUdpExchangeResponse {
    target: String,
    probe_only: bool,
    bytes_sent: usize,
    bytes_received: usize,
    payload_text: String,
    stdout: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestUdpFailure {
    exit_code: i32,
    stderr: String,
}

impl GuestUdpFailure {
    fn new(exit_code: i32, message: impl Into<String>) -> Self {
        let mut stderr = message.into();
        if !stderr.ends_with('\n') {
            stderr.push('\n');
        }
        Self { exit_code, stderr }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuestDnsLookupMode {
    Nslookup,
    GetentHosts,
}

impl GuestDnsLookupMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Nslookup => "nslookup",
            Self::GetentHosts => "getent_hosts",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestDnsLookupResponse {
    stdout: String,
    resolved_addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestDnsLookupFailure {
    exit_code: i32,
    stderr: String,
}

impl GuestDnsLookupFailure {
    fn new(exit_code: i32, message: impl Into<String>) -> Self {
        let mut stderr = message.into();
        if !stderr.ends_with('\n') {
            stderr.push('\n');
        }
        Self { exit_code, stderr }
    }
}

fn parse_guest_egress_command(command: &str) -> Result<GuestEgressRequest> {
    let tokens = command.split_whitespace().collect::<Vec<_>>();
    match tokens.as_slice() {
        ["fetch", url] => Ok(GuestEgressRequest {
            method: GuestEgressMethod::Get,
            url: (*url).to_owned(),
        }),
        ["curl", url] => Ok(GuestEgressRequest {
            method: GuestEgressMethod::Get,
            url: (*url).to_owned(),
        }),
        ["curl", "-I", url] | ["curl", "--head", url] => Ok(GuestEgressRequest {
            method: GuestEgressMethod::Head,
            url: (*url).to_owned(),
        }),
        ["fetch"] => Err(PlatformError::invalid("fetch requires one URL argument")),
        ["curl"] => Err(PlatformError::invalid("curl requires a URL argument")),
        _ if command.starts_with("curl") => Err(PlatformError::invalid(
            "guest curl supports only `curl <url>` or `curl -I <url>`",
        )),
        _ if command.starts_with("fetch") => Err(PlatformError::invalid(
            "guest fetch supports only `fetch <url>`",
        )),
        _ => Err(PlatformError::invalid("unsupported guest egress command")),
    }
}

fn next_guest_command_token(input: &str) -> Option<(&str, &str)> {
    let trimmed = input.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    Some((&trimmed[..end], &trimmed[end..]))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedGuestSocketCommand {
    host: String,
    port: u16,
    payload: Option<String>,
    probe_only: bool,
    udp: bool,
}

fn parse_guest_netcat_command(command: &str) -> Result<ParsedGuestSocketCommand> {
    let trimmed = command.trim();
    let remainder = if let Some(value) = trimmed.strip_prefix("nc") {
        value
    } else if let Some(value) = trimmed.strip_prefix("netcat") {
        value
    } else {
        return Err(PlatformError::invalid("unsupported guest socket command"));
    };
    let mut remainder = remainder.trim_start();
    let mut probe_only = false;
    let mut udp = false;
    loop {
        let Some((token, tail)) = next_guest_command_token(remainder) else {
            break;
        };
        if !token.starts_with('-') || token == "-" {
            break;
        }
        for flag in token.trim_start_matches('-').chars() {
            match flag {
                'z' => probe_only = true,
                'u' => udp = true,
                _ => {
                    return Err(PlatformError::invalid(
                        "guest socket command supports only `-z` and `-u` flags",
                    ));
                }
            }
        }
        remainder = tail.trim_start();
    }
    let (host, remainder) = next_guest_command_token(remainder)
        .ok_or_else(|| PlatformError::invalid("guest socket command requires a host"))?;
    let (port, payload) = next_guest_command_token(remainder)
        .ok_or_else(|| PlatformError::invalid("guest socket command requires a port"))?;
    let port = port.parse::<u16>().map_err(|error| {
        PlatformError::invalid("guest socket command port must be a valid u16")
            .with_detail(error.to_string())
    })?;
    if host.chars().any(char::is_whitespace) {
        return Err(PlatformError::invalid(
            "guest socket command host may not contain whitespace",
        ));
    }
    let payload = payload.trim();
    let payload = if probe_only || payload.is_empty() {
        None
    } else {
        let payload = strip_wrapping_quotes(payload);
        if payload.len() > MAX_GUEST_TCP_PAYLOAD_BYTES {
            return Err(PlatformError::invalid(
                "guest socket command payload exceeds 64 KiB",
            ));
        }
        Some(payload.to_owned())
    };
    Ok(ParsedGuestSocketCommand {
        host: host.to_owned(),
        port,
        payload,
        probe_only,
        udp,
    })
}

fn parse_guest_tcp_connect_command(command: &str) -> Result<GuestTcpConnectRequest> {
    let request = parse_guest_netcat_command(command)?;
    if request.udp {
        return Err(PlatformError::invalid(
            "guest tcp connect command may not include the `-u` flag",
        ));
    }
    Ok(GuestTcpConnectRequest {
        host: request.host,
        port: request.port,
        payload: request.payload,
        probe_only: request.probe_only,
    })
}

fn parse_guest_udp_exchange_command(command: &str) -> Result<GuestUdpExchangeRequest> {
    let request = parse_guest_netcat_command(command)?;
    if !request.udp {
        return Err(PlatformError::invalid(
            "guest udp exchange command requires the `-u` flag",
        ));
    }
    Ok(GuestUdpExchangeRequest {
        host: request.host,
        port: request.port,
        payload: request.payload,
        probe_only: request.probe_only,
    })
}

fn parse_guest_tcp_wire_request(value: &str) -> Result<GuestTcpConnectRequest> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("probe") {
        return Ok(GuestTcpConnectRequest {
            host: String::new(),
            port: 0,
            payload: None,
            probe_only: true,
        });
    }
    if let Some(payload) = value.strip_prefix("exchange\n") {
        return Ok(GuestTcpConnectRequest {
            host: String::new(),
            port: 0,
            payload: Some(payload.to_owned()),
            probe_only: false,
        });
    }
    if trimmed.eq_ignore_ascii_case("exchange") {
        return Ok(GuestTcpConnectRequest {
            host: String::new(),
            port: 0,
            payload: None,
            probe_only: false,
        });
    }
    Err(PlatformError::invalid(
        "guest tcp wire mode must be `probe` or `exchange`",
    ))
}

fn parse_guest_udp_wire_request(value: &str) -> Result<GuestUdpExchangeRequest> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("probe") {
        return Ok(GuestUdpExchangeRequest {
            host: String::new(),
            port: 0,
            payload: None,
            probe_only: true,
        });
    }
    if let Some(payload) = value.strip_prefix("exchange\n") {
        return Ok(GuestUdpExchangeRequest {
            host: String::new(),
            port: 0,
            payload: Some(payload.to_owned()),
            probe_only: false,
        });
    }
    if trimmed.eq_ignore_ascii_case("exchange") {
        return Ok(GuestUdpExchangeRequest {
            host: String::new(),
            port: 0,
            payload: None,
            probe_only: false,
        });
    }
    Err(PlatformError::invalid(
        "guest udp wire mode must be `probe` or `exchange`",
    ))
}

fn parse_guest_dns_lookup_command(command: &str) -> Result<(GuestDnsLookupMode, String)> {
    if let Some(host) = command.strip_prefix("nslookup") {
        let host = host.trim();
        if host.is_empty() {
            return Err(PlatformError::invalid("nslookup requires a hostname"));
        }
        return Ok((GuestDnsLookupMode::Nslookup, host.to_owned()));
    }
    if let Some(rest) = command.strip_prefix("getent") {
        let rest = rest.trim();
        let mut parts = rest.split_whitespace();
        let database = parts
            .next()
            .ok_or_else(|| PlatformError::invalid("getent requires a database"))?;
        if database != "hosts" {
            return Err(PlatformError::invalid(
                "guest getent supports only `getent hosts <hostname>`",
            ));
        }
        let host = parts
            .next()
            .ok_or_else(|| PlatformError::invalid("getent hosts requires a hostname"))?;
        if parts.next().is_some() {
            return Err(PlatformError::invalid(
                "guest getent supports only one hostname argument",
            ));
        }
        return Ok((GuestDnsLookupMode::GetentHosts, host.to_owned()));
    }
    Err(PlatformError::invalid(
        "unsupported guest dns lookup command",
    ))
}

fn guest_egress_fetch(
    url: &str,
    method: GuestEgressMethod,
) -> std::result::Result<GuestEgressResponse, GuestEgressFailure> {
    let target = parse_guest_egress_target(url)?;
    match target.scheme {
        GuestEgressScheme::Http => guest_egress_fetch_http(&target, method),
        GuestEgressScheme::Https => guest_egress_fetch_https_via_curl(&target, method),
    }
}

fn parse_guest_egress_target(
    url: &str,
) -> std::result::Result<GuestEgressTarget, GuestEgressFailure> {
    let trimmed = url.trim();
    let (scheme, remainder) = trimmed
        .split_once("://")
        .ok_or_else(|| GuestEgressFailure::new(22, "guest egress URL must include a scheme"))?;
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "http" => GuestEgressScheme::Http,
        "https" => GuestEgressScheme::Https,
        _ => {
            return Err(GuestEgressFailure::new(
                22,
                "guest egress URL scheme must be http or https",
            ));
        }
    };
    let (authority, path_and_query) = if let Some((authority, suffix)) = remainder.split_once('/') {
        (authority, format!("/{suffix}"))
    } else {
        (remainder, String::from("/"))
    };
    if authority.is_empty() || authority.contains('@') || authority.contains('[') {
        return Err(GuestEgressFailure::new(
            22,
            "guest egress URL must use a plain hostname or IPv4 authority",
        ));
    }
    let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
        if authority.matches(':').count() == 1 {
            let parsed_port = port.parse::<u16>().map_err(|error| {
                GuestEgressFailure::new(22, format!("invalid guest egress URL port: {error}"))
            })?;
            (host, parsed_port)
        } else {
            (authority, default_guest_egress_port(scheme))
        }
    } else {
        (authority, default_guest_egress_port(scheme))
    };
    if host.is_empty() || host.chars().any(char::is_whitespace) {
        return Err(GuestEgressFailure::new(
            22,
            "guest egress URL host may not be empty",
        ));
    }
    Ok(GuestEgressTarget {
        scheme,
        url: trimmed.to_owned(),
        authority: authority.to_owned(),
        host: host.to_owned(),
        port,
        path_and_query,
    })
}

fn default_guest_egress_port(scheme: GuestEgressScheme) -> u16 {
    match scheme {
        GuestEgressScheme::Http => 80,
        GuestEgressScheme::Https => 443,
    }
}

fn guest_tcp_connect(
    target: &str,
    request: &GuestTcpConnectRequest,
) -> std::result::Result<GuestTcpConnectResponse, GuestTcpFailure> {
    let resolved = parse_guest_tcp_target(target)?;
    let mut stream = connect_guest_tcp_stream(&resolved)?;
    let _ = stream.set_read_timeout(Some(GUEST_EGRESS_TIMEOUT));
    let _ = stream.set_write_timeout(Some(GUEST_EGRESS_TIMEOUT));

    let payload = if request.probe_only {
        None
    } else {
        request.payload.as_deref()
    };
    let mut bytes_sent = 0usize;
    if let Some(payload) = payload {
        stream
            .write_all(payload.as_bytes())
            .map_err(guest_tcp_io_failure)?;
        bytes_sent = payload.len();
    }
    let _ = stream.shutdown(Shutdown::Write);

    let mut response_bytes = Vec::new();
    if !request.probe_only {
        let _ = stream.read_to_end(&mut response_bytes);
    }

    Ok(GuestTcpConnectResponse {
        target: resolved,
        probe_only: request.probe_only,
        bytes_sent,
        bytes_received: response_bytes.len(),
        payload_text: payload.unwrap_or_default().to_owned(),
        stdout: String::from_utf8_lossy(&response_bytes).into_owned(),
    })
}

fn parse_guest_tcp_target(target: &str) -> std::result::Result<String, GuestTcpFailure> {
    let trimmed = target.trim();
    let (host, port) = trimmed
        .rsplit_once(':')
        .ok_or_else(|| GuestTcpFailure::new(22, "guest tcp target must use `<host>:<port>`"))?;
    if host.is_empty() || host.chars().any(char::is_whitespace) {
        return Err(GuestTcpFailure::new(
            22,
            "guest tcp target host may not be empty",
        ));
    }
    let port = port.parse::<u16>().map_err(|error| {
        GuestTcpFailure::new(22, format!("invalid guest tcp target port: {error}"))
    })?;
    Ok(format!("{host}:{port}"))
}

fn connect_guest_tcp_stream(target: &str) -> std::result::Result<TcpStream, GuestTcpFailure> {
    let addresses = target.to_socket_addrs().map_err(|error| {
        GuestTcpFailure::new(
            6,
            format!("guest tcp relay failed to resolve target: {error}"),
        )
    })?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect(address) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.map_or_else(
        || GuestTcpFailure::new(7, "guest tcp relay found no reachable target address"),
        guest_tcp_io_failure,
    ))
}

fn guest_tcp_io_failure(error: std::io::Error) -> GuestTcpFailure {
    let exit_code = match error.kind() {
        std::io::ErrorKind::TimedOut => 28,
        std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::NotConnected
        | std::io::ErrorKind::AddrInUse
        | std::io::ErrorKind::AddrNotAvailable => 7,
        _ => 56,
    };
    GuestTcpFailure::new(exit_code, format!("guest tcp relay failed: {error}"))
}

fn guest_udp_exchange(
    target: &str,
    request: &GuestUdpExchangeRequest,
) -> std::result::Result<GuestUdpExchangeResponse, GuestUdpFailure> {
    let resolved = parse_guest_tcp_target(target)
        .map_err(|failure| GuestUdpFailure::new(failure.exit_code, failure.stderr))?;
    let addresses = resolved.to_socket_addrs().map_err(|error| {
        GuestUdpFailure::new(
            6,
            format!("guest udp relay failed to resolve target: {error}"),
        )
    })?;
    let mut last_error = None;
    for address in addresses {
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => socket,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let _ = socket.set_read_timeout(Some(GUEST_EGRESS_TIMEOUT));
        let _ = socket.set_write_timeout(Some(GUEST_EGRESS_TIMEOUT));
        if let Err(error) = socket.connect(address) {
            last_error = Some(error);
            continue;
        }
        let payload = if request.probe_only {
            None
        } else {
            request.payload.as_deref()
        };
        let mut bytes_sent = 0usize;
        if let Some(payload) = payload {
            socket
                .send(payload.as_bytes())
                .map_err(guest_udp_io_failure)?;
            bytes_sent = payload.len();
        }
        let mut buffer = vec![0_u8; MAX_GUEST_TCP_PAYLOAD_BYTES];
        let bytes_received = if request.probe_only {
            0
        } else {
            match socket.recv(&mut buffer) {
                Ok(read) => read,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    0
                }
                Err(error) => return Err(guest_udp_io_failure(error)),
            }
        };
        buffer.truncate(bytes_received);
        return Ok(GuestUdpExchangeResponse {
            target: resolved.clone(),
            probe_only: request.probe_only,
            bytes_sent,
            bytes_received,
            payload_text: payload.unwrap_or_default().to_owned(),
            stdout: String::from_utf8_lossy(&buffer).into_owned(),
        });
    }
    Err(last_error.map_or_else(
        || GuestUdpFailure::new(7, "guest udp relay found no reachable target address"),
        guest_udp_io_failure,
    ))
}

fn guest_udp_io_failure(error: std::io::Error) -> GuestUdpFailure {
    let exit_code = match error.kind() {
        std::io::ErrorKind::TimedOut => 28,
        std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::NotConnected
        | std::io::ErrorKind::AddrInUse
        | std::io::ErrorKind::AddrNotAvailable => 7,
        _ => 56,
    };
    GuestUdpFailure::new(exit_code, format!("guest udp relay failed: {error}"))
}

fn guest_dns_lookup(
    mode: GuestDnsLookupMode,
    host: &str,
) -> std::result::Result<GuestDnsLookupResponse, GuestDnsLookupFailure> {
    let query = host.trim();
    if query.is_empty() || query.chars().any(char::is_whitespace) {
        return Err(GuestDnsLookupFailure::new(
            22,
            "guest dns lookup requires a non-empty hostname",
        ));
    }
    let mut addresses = BTreeSet::new();
    for address in (query, 0).to_socket_addrs().map_err(|error| {
        GuestDnsLookupFailure::new(
            6,
            format!("guest dns lookup failed to resolve host: {error}"),
        )
    })? {
        let _ = addresses.insert(address.ip().to_string());
    }
    if addresses.is_empty() {
        return Err(GuestDnsLookupFailure::new(
            6,
            "guest dns lookup returned no addresses",
        ));
    }
    let resolved_addresses = addresses.into_iter().collect::<Vec<_>>();
    let stdout = match mode {
        GuestDnsLookupMode::Nslookup => {
            let mut rendered = format!(
                "Server:\t\t{dns}\nAddress:\t{dns}#53\n\nNon-authoritative answer:\nName:\t{query}\n",
                dns = GUEST_NETWORK_DNS_IPV4,
            );
            for address in &resolved_addresses {
                rendered.push_str(&format!("Address:\t{address}\n"));
            }
            rendered
        }
        GuestDnsLookupMode::GetentHosts => resolved_addresses
            .iter()
            .map(|address| format!("{address} {query}\n"))
            .collect::<String>(),
    };
    Ok(GuestDnsLookupResponse {
        stdout,
        resolved_addresses,
    })
}

fn guest_egress_fetch_http(
    target: &GuestEgressTarget,
    method: GuestEgressMethod,
) -> std::result::Result<GuestEgressResponse, GuestEgressFailure> {
    let address = format!("{}:{}", target.host, target.port);
    let mut stream = TcpStream::connect(address).map_err(guest_egress_io_failure)?;
    let _ = stream.set_read_timeout(Some(GUEST_EGRESS_TIMEOUT));
    let _ = stream.set_write_timeout(Some(GUEST_EGRESS_TIMEOUT));
    let request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        method.as_str(),
        target.path_and_query,
        target.authority,
        GUEST_EGRESS_USER_AGENT,
    );
    stream
        .write_all(request.as_bytes())
        .map_err(guest_egress_io_failure)?;
    let mut response_bytes = Vec::new();
    stream
        .read_to_end(&mut response_bytes)
        .map_err(guest_egress_io_failure)?;
    parse_guest_egress_http_response(target.url.as_str(), method, &response_bytes)
}

fn guest_egress_fetch_https_via_curl(
    target: &GuestEgressTarget,
    method: GuestEgressMethod,
) -> std::result::Result<GuestEgressResponse, GuestEgressFailure> {
    let root = std::env::temp_dir().join(format!("uhost-softvm-egress-{}", std::process::id()));
    fs::create_dir_all(&root).map_err(guest_egress_io_failure)?;
    let token = splitmix64(u64::from(std::process::id()) ^ target.url.len() as u64);
    let header_path = root.join(format!("headers-{token:016x}.txt"));
    let body_path = root.join(format!("body-{token:016x}.bin"));
    let mut command = Command::new("curl");
    command
        .arg("--silent")
        .arg("--show-error")
        .arg("--connect-timeout")
        .arg("5")
        .arg("--max-time")
        .arg("10")
        .arg("--dump-header")
        .arg(&header_path)
        .arg("--output")
        .arg(&body_path)
        .arg("--user-agent")
        .arg(GUEST_EGRESS_USER_AGENT);
    if method == GuestEgressMethod::Head {
        let _ = command.arg("--head");
    }
    let output = command.arg(target.url.as_str()).output().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            GuestEgressFailure::new(
                127,
                "host HTTPS relay requires `curl` to be available on the runner host",
            )
        } else {
            guest_egress_io_failure(error)
        }
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let exit_code = output.status.code().unwrap_or(56);
        let _ = fs::remove_file(&header_path);
        let _ = fs::remove_file(&body_path);
        return Err(GuestEgressFailure::new(
            exit_code,
            if stderr.is_empty() {
                String::from("host HTTPS relay failed")
            } else {
                stderr
            },
        ));
    }
    let header_bytes = fs::read(&header_path).map_err(guest_egress_io_failure)?;
    let body_bytes = fs::read(&body_path).unwrap_or_default();
    let _ = fs::remove_file(&header_path);
    let _ = fs::remove_file(&body_path);
    build_guest_egress_response(target.url.as_str(), method, &header_bytes, &body_bytes)
}

fn guest_egress_io_failure(error: std::io::Error) -> GuestEgressFailure {
    let exit_code = match error.kind() {
        std::io::ErrorKind::TimedOut => 28,
        std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::NotConnected
        | std::io::ErrorKind::AddrInUse
        | std::io::ErrorKind::AddrNotAvailable => 7,
        _ => 56,
    };
    GuestEgressFailure::new(exit_code, format!("guest egress relay failed: {error}"))
}

fn parse_guest_egress_http_response(
    url: &str,
    method: GuestEgressMethod,
    response_bytes: &[u8],
) -> std::result::Result<GuestEgressResponse, GuestEgressFailure> {
    let header_end = find_byte_sequence(response_bytes, b"\r\n\r\n").ok_or_else(|| {
        GuestEgressFailure::new(
            52,
            "guest egress relay response is missing a header terminator",
        )
    })?;
    let header_bytes = &response_bytes[..header_end];
    let body_bytes = &response_bytes[header_end.saturating_add(4)..];
    build_guest_egress_response(url, method, header_bytes, body_bytes)
}

fn build_guest_egress_response(
    url: &str,
    method: GuestEgressMethod,
    header_bytes: &[u8],
    body_bytes: &[u8],
) -> std::result::Result<GuestEgressResponse, GuestEgressFailure> {
    let ParsedHttpHeaderBlock {
        status_line,
        http_status,
        headers,
        normalized_header_text: headers_text,
    } = parse_http_header_block(header_bytes)?;
    let transfer_encoding = find_http_header_value(&headers, "transfer-encoding")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let decoded_body = if transfer_encoding.contains("chunked") {
        decode_http_chunked_body(body_bytes)?
    } else {
        body_bytes.to_vec()
    };
    let content_type = find_http_header_value(&headers, "content-type").unwrap_or_default();
    let body_len = decoded_body.len();
    let truncated = body_len > MAX_GUEST_EGRESS_BODY_BYTES;
    let captured_body = &decoded_body[..body_len.min(MAX_GUEST_EGRESS_BODY_BYTES)];
    let body_text = if method == GuestEgressMethod::Head {
        String::new()
    } else {
        String::from_utf8_lossy(captured_body).into_owned()
    };
    Ok(GuestEgressResponse {
        url: url.to_owned(),
        method,
        http_status,
        status_line,
        headers_text,
        body_text,
        content_type,
        body_bytes: body_len,
        truncated,
    })
}

fn parse_http_header_block(
    header_bytes: &[u8],
) -> std::result::Result<ParsedHttpHeaderBlock, GuestEgressFailure> {
    let header_text = String::from_utf8_lossy(header_bytes).replace("\r\n", "\n");
    let normalized_header_text = if header_text.ends_with('\n') {
        header_text
    } else {
        format!("{header_text}\n")
    };
    let mut lines = normalized_header_text.lines();
    let status_line = lines.next().ok_or_else(|| {
        GuestEgressFailure::new(52, "guest egress response is missing an HTTP status line")
    })?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(GuestEgressFailure::new(
            52,
            "guest egress response does not start with an HTTP status line",
        ));
    }
    let http_status = status_parts
        .next()
        .ok_or_else(|| {
            GuestEgressFailure::new(52, "guest egress response is missing an HTTP status code")
        })?
        .parse::<u16>()
        .map_err(|error| {
            GuestEgressFailure::new(52, format!("invalid HTTP status code: {error}"))
        })?;
    let headers = lines
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (name, value) = line.split_once(':').ok_or_else(|| {
                GuestEgressFailure::new(52, "guest egress response contains an invalid header")
            })?;
            Ok((name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect::<std::result::Result<Vec<_>, GuestEgressFailure>>()?;
    Ok(ParsedHttpHeaderBlock {
        status_line: status_line.to_owned(),
        http_status,
        headers,
        normalized_header_text,
    })
}

fn find_http_header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

fn decode_http_chunked_body(body_bytes: &[u8]) -> std::result::Result<Vec<u8>, GuestEgressFailure> {
    let mut cursor = 0usize;
    let mut decoded = Vec::new();
    while cursor < body_bytes.len() {
        let line_end = find_byte_sequence(&body_bytes[cursor..], b"\r\n").ok_or_else(|| {
            GuestEgressFailure::new(
                52,
                "chunked guest egress body is missing a size line terminator",
            )
        })?;
        let line = &body_bytes[cursor..cursor.saturating_add(line_end)];
        let size = usize::from_str_radix(
            String::from_utf8_lossy(line)
                .split(';')
                .next()
                .unwrap_or_default()
                .trim(),
            16,
        )
        .map_err(|error| GuestEgressFailure::new(52, format!("invalid chunk size: {error}")))?;
        cursor = cursor.saturating_add(line_end + 2);
        if size == 0 {
            break;
        }
        let next_cursor = cursor.saturating_add(size);
        if next_cursor > body_bytes.len() {
            return Err(GuestEgressFailure::new(
                52,
                "chunked guest egress body ended before the declared chunk size",
            ));
        }
        decoded.extend_from_slice(&body_bytes[cursor..next_cursor]);
        cursor = next_cursor;
        if body_bytes.get(cursor..cursor.saturating_add(2)) != Some(b"\r\n") {
            return Err(GuestEgressFailure::new(
                52,
                "chunked guest egress body is missing a chunk terminator",
            ));
        }
        cursor = cursor.saturating_add(2);
    }
    Ok(decoded)
}

fn find_byte_sequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn native_meminfo_report(guest_memory_bytes: u64) -> String {
    let total_kib = guest_memory_bytes / 1024;
    let available_kib = total_kib.saturating_sub(total_kib / 8);
    format!("MemTotal:       {total_kib} kB\nMemAvailable:   {available_kib} kB\n")
}

struct NativeUnixBenchMetrics {
    dhrystone: f64,
    whetstone: f64,
    execl: f64,
    copy: f64,
    index: f64,
    source_kind: UnixBenchMetricSourceKind,
    source_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnixBenchMetricSourceKind {
    SyntheticBaseline,
    HostCalibratedFull,
    HostCalibratedPartial,
}

impl UnixBenchMetricSourceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::SyntheticBaseline => "synthetic_baseline",
            Self::HostCalibratedFull => "host_calibrated_full",
            Self::HostCalibratedPartial => "host_calibrated_partial",
        }
    }
}

#[derive(Debug, Clone)]
struct HostUnixBenchScore {
    index: f64,
    source_path: PathBuf,
    partial: bool,
}

fn extract_unixbench_index_score(text: &str) -> Option<f64> {
    for line in text.lines() {
        if !line.contains("System Benchmarks Index Score") {
            continue;
        }
        for token in line.split_whitespace().rev() {
            let trimmed = token
                .trim_matches(|character: char| !character.is_ascii_digit() && character != '.');
            if let Ok(value) = trimmed.parse::<f64>() {
                return Some(value);
            }
        }
    }
    None
}

fn host_unixbench_results_dir() -> PathBuf {
    std::env::var_os("UHOST_SOFTVM_HOST_UNIXBENCH_RESULTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/opt/byte-unixbench/UnixBench/results"))
}

fn read_host_unixbench_score(path: &Path) -> Option<HostUnixBenchScore> {
    let text = fs::read_to_string(path).ok()?;
    let index = extract_unixbench_index_score(&text)?;
    Some(HostUnixBenchScore {
        index,
        source_path: path.to_path_buf(),
        partial: text.contains("System Benchmarks Index Score (Partial Only)"),
    })
}

fn latest_host_unixbench_score_in_dir(root: &Path) -> Option<HostUnixBenchScore> {
    let mut latest = None;
    for entry in fs::read_dir(root).ok()? {
        let entry = entry.ok()?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name()?.to_string_lossy();
        if name.ends_with(".html") || name.ends_with(".log") {
            continue;
        }
        let Some(score) = read_host_unixbench_score(&path) else {
            continue;
        };
        let modified = entry.metadata().ok()?.modified().ok()?;
        match latest {
            Some((current_modified, _)) if current_modified >= modified => {}
            _ => latest = Some((modified, score)),
        }
    }
    latest.map(|(_, score)| score)
}

fn latest_host_unixbench_score() -> Option<HostUnixBenchScore> {
    if let Some(path) = std::env::var_os("UHOST_SOFTVM_HOST_UNIXBENCH_RESULT") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return read_host_unixbench_score(&path);
        }
    }
    latest_host_unixbench_score_in_dir(&host_unixbench_results_dir())
}

fn scale_unixbench_metrics_to_index(
    mut metrics: NativeUnixBenchMetrics,
    target_index: f64,
) -> NativeUnixBenchMetrics {
    if target_index > 0.0 && metrics.index > 0.0 {
        let scale = target_index / metrics.index;
        metrics.dhrystone *= scale;
        metrics.whetstone *= scale;
        metrics.execl *= scale;
        metrics.copy *= scale;
        metrics.index = target_index;
    }
    metrics
}

fn scale_unixbench_metrics_to_host_score(
    metrics: NativeUnixBenchMetrics,
    host_score: &HostUnixBenchScore,
) -> NativeUnixBenchMetrics {
    let mut scaled = scale_unixbench_metrics_to_index(metrics, host_score.index);
    scaled.source_kind = if host_score.partial {
        UnixBenchMetricSourceKind::HostCalibratedPartial
    } else {
        UnixBenchMetricSourceKind::HostCalibratedFull
    };
    scaled.source_path = Some(host_score.source_path.clone());
    scaled
}

fn synthetic_unixbench_metrics(vcpu: u16, guest_memory_bytes: u64) -> NativeUnixBenchMetrics {
    let vcpu = f64::from(vcpu.max(1));
    let memory_gib = (guest_memory_bytes as f64) / 1024.0 / 1024.0 / 1024.0;
    let dhrystone = 850_000.0 * vcpu * (1.0 + memory_gib.max(1.0).log2() * 0.07);
    let whetstone = 220.0 * vcpu * (1.0 + memory_gib.max(1.0).log2() * 0.05);
    let execl = 18.0 * vcpu;
    let copy = 12_500.0 * vcpu * memory_gib.max(1.0);
    let index = (dhrystone / 11_6700.0 * 100.0
        + whetstone / 55.0 * 10.0
        + execl / 43.0 * 2.0
        + copy / 3960.0 * 3.0)
        / 4.0;
    NativeUnixBenchMetrics {
        dhrystone,
        whetstone,
        execl,
        copy,
        index,
        source_kind: UnixBenchMetricSourceKind::SyntheticBaseline,
        source_path: None,
    }
}

fn native_unixbench_metrics(vcpu: u16, guest_memory_bytes: u64) -> NativeUnixBenchMetrics {
    let synthetic = synthetic_unixbench_metrics(vcpu, guest_memory_bytes);
    if let Some(host_score) = latest_host_unixbench_score() {
        return scale_unixbench_metrics_to_host_score(synthetic, &host_score);
    }
    synthetic
}

fn render_unixbench_summary_from_guest_metrics(
    execution: &SoftVmExecutionCore,
    control: &SoftVmGuestControl,
) -> Result<String> {
    let read_metric = |path: &str| -> Result<f64> {
        read_guest_file(execution, control, path)
            .ok_or_else(|| PlatformError::unavailable(format!("missing guest metric `{path}`")))?
            .trim()
            .parse::<f64>()
            .map_err(|error| {
                PlatformError::invalid(format!("invalid guest metric `{path}`"))
                    .with_detail(error.to_string())
            })
    };
    let dhrystone = read_metric("/var/lib/unixbench/metrics/dhrystone")?;
    let whetstone = read_metric("/var/lib/unixbench/metrics/whetstone")?;
    let execl = read_metric("/var/lib/unixbench/metrics/execl")?;
    let copy = read_metric("/var/lib/unixbench/metrics/copy")?;
    let index = read_metric("/var/lib/unixbench/metrics/index")?;
    let source = read_guest_file(execution, control, "/var/lib/unixbench/metrics/source")
        .unwrap_or_else(|| String::from("synthetic_baseline\n"));
    let source = source.trim();
    let source_path = read_guest_file(execution, control, "/var/lib/unixbench/metrics/source_path")
        .unwrap_or_default();
    let source_path = source_path.trim();
    let source_line = if source_path.is_empty() {
        format!("Measurement source: {source}\n")
    } else {
        format!("Measurement source: {source} ({source_path})\n")
    };
    Ok(format!(
        "UVM Native UnixBench-style Summary\n\
{source_line}\
System Benchmarks Index Values               BASELINE       RESULT    INDEX\n\
Dhrystone 2 using register variables         116700.0    {dhrystone:.1}    {d_index:.1}\n\
Double-Precision Whetstone                       55.0       {whetstone:.1}    {w_index:.1}\n\
Execl Throughput                                 43.0         {execl:.1}     {e_index:.1}\n\
File Copy 1024 bufsize 2000 maxblocks          3960.0      {copy:.1}   {c_index:.1}\n\
                                                                    ========\n\
System Benchmarks Index Score                                         {index:.1}\n",
        d_index = dhrystone / 116_700.0 * 10.0,
        w_index = whetstone / 55.0,
        e_index = execl / 43.0 * 10.0,
        c_index = copy / 3960.0 * 10.0,
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        net::{TcpListener, UdpSocket},
        path::{Path, PathBuf},
        sync::OnceLock,
        thread,
    };

    use super::{
        BLOCK_CONTROL_ROLE_INSTALL_MEDIA, BLOCK_CONTROL_ROLE_PRIMARY_DISK,
        DEFAULT_BLOCK_SIZE_BYTES, DEVICE_INTERRUPT_CONTROL_ACK, DEVICE_INTERRUPT_CONTROL_MASK,
        DEVICE_INTERRUPT_CONTROL_UNMASK, DEVICE_INTERRUPT_STATE_LATCHED,
        DEVICE_INTERRUPT_STATE_MASKED, DEVICE_INTERRUPT_STATE_PENDING,
        DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET, DEVICE_MMIO_METADATA_OFFSET,
        DEVICE_MMIO_QUEUE_CONTROL_OFFSET, DEVICE_MMIO_STATUS_OFFSET,
        GUEST_KERNEL_ROUTE_DIRECTORY_INDEX, GUEST_KERNEL_ROUTE_FILE_READ,
        GUEST_KERNEL_ROUTE_FILE_TOUCH, GUEST_KERNEL_ROUTE_SERVICE_STATUS,
        GUEST_KERNEL_SERVICE_DESCRIPTOR_BYTES, GUEST_KERNEL_SERVICE_ENTRIES,
        GUEST_KERNEL_SERVICE_KIND_INDEX, GUEST_KERNEL_SERVICE_KIND_READ_ONLY,
        GUEST_KERNEL_SERVICE_VERSION, GUEST_RAM_DATA_BASE, GuestFileProjection, HostUnixBenchScore,
        ISA_OPCODE_CALL_ABS64, ISA_OPCODE_HALT, ISA_REGISTER_ARG0, ISA_REGISTER_ARG1,
        ISA_REGISTER_ARG2, ISA_REGISTER_ARG3, NATIVE_CALL_BOOT_DEVICE_TRANSFER,
        NATIVE_CALL_BOOT_SERVICE_ROUTE, NATIVE_CALL_DIRECT_KERNEL_ENTRY,
        NATIVE_CALL_FIRMWARE_DISPATCH, NATIVE_CALL_GUEST_CAT, NATIVE_CALL_GUEST_LS,
        NATIVE_CALL_GUEST_SYSTEMCTL_STATUS, NATIVE_CALL_INSTALL_MEDIA_PROBE,
        NATIVE_CALL_USERSPACE_CONTROL, NativeUnixBenchMetrics, SoftVmArtifactPolicy,
        SoftVmInstance, SoftVmProgramOutcome, SoftVmResidentProgram, SoftVmRuntimeSpec,
        UnixBenchMetricSourceKind, boot_artifact_display_name, boot_service_stage_sequence,
        build_boot_service_handler, direct_kernel_command_line, emit_call_abs64, emit_halt,
        emit_mmio_read64, emit_mmio_write64, emit_mov_imm64, emit_native_call, emit_ret,
        encode_guest_kernel_request, extract_unixbench_index_score, guest_directory_index_path,
        guest_kernel_route_descriptor, guest_kernel_service_descriptor, guest_sha256_index_path,
        latest_host_unixbench_score_in_dir, packed_u32_pair, padded_le_u64, read_guest_file,
        scale_unixbench_metrics_to_host_score, scale_unixbench_metrics_to_index, splitmix64,
        synthetic_unixbench_metrics, unixbench_metric_projections, upsert_guest_file_batch,
        upsert_guest_file_raw,
    };
    use uhost_core::sha256_hex;
    use uhost_uvm::{
        BootDevice, BootPath, DeviceModel, ExecutionClass, GuestArchitecture, MachineFamily,
    };
    use uhost_uvm_machine::MachineSpec;

    fn staged_artifact_path(file_name: &str, bytes: &[u8]) -> String {
        static ROOT: OnceLock<std::path::PathBuf> = OnceLock::new();
        let root = ROOT.get_or_init(|| {
            let path = std::env::temp_dir().join(format!(
                "uhost-softvm-exec-artifacts-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap_or_else(|error| panic!("{error}"));
            path
        });
        let path = root.join(file_name);
        if !path.exists() {
            std::fs::write(&path, bytes).unwrap_or_else(|error| panic!("{error}"));
        }
        path.to_string_lossy().into_owned()
    }

    fn staged_disk_artifact_source() -> String {
        staged_artifact_path("disk.raw", b"softvm-test-disk")
    }

    fn staged_install_artifact_source() -> String {
        staged_artifact_path("installer.iso", b"softvm-test-install-media")
    }

    fn staged_kernel_artifact_source() -> String {
        staged_artifact_path("vmlinuz", b"softvm-test-kernel")
    }

    fn spawn_http_probe_server(
        status_line: &'static str,
        headers: &'static [(&'static str, &'static str)],
        body: &'static str,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let headers = headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .collect::<String>();
        let body = body.to_owned();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut request_bytes = [0u8; 4096];
            let _ = stream.read(&mut request_bytes);
            let response = format!(
                "{status_line}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        });
        format!("http://{address}")
    }

    fn spawn_tcp_probe_server(response: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let response = response.to_owned();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut request_bytes = [0u8; 4096];
            let _ = stream.read(&mut request_bytes);
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        });
        address.to_string()
    }

    fn spawn_udp_probe_server(response: &'static str) -> String {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
        let address = socket
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let response = response.as_bytes().to_vec();
        thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            let (read, peer) = socket
                .recv_from(&mut buffer)
                .unwrap_or_else(|error| panic!("{error}"));
            if read > 0 {
                socket
                    .send_to(&response, peer)
                    .unwrap_or_else(|error| panic!("{error}"));
            }
        });
        address.to_string()
    }

    fn machine() -> MachineSpec {
        MachineSpec::new(
            MachineFamily::GeneralPurposePci,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioBalanced,
            BootPath::GeneralPurpose,
            "uefi_standard",
            staged_disk_artifact_source(),
            None,
            BootDevice::Disk,
        )
        .unwrap_or_else(|error| panic!("{error}"))
    }

    fn microvm_machine() -> MachineSpec {
        MachineSpec::new(
            MachineFamily::MicrovmLinux,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioMinimal,
            BootPath::MicroVm,
            staged_kernel_artifact_source(),
            staged_disk_artifact_source(),
            None,
            BootDevice::Disk,
        )
        .unwrap_or_else(|error| panic!("{error}"))
    }

    fn aarch64_machine() -> MachineSpec {
        MachineSpec::new(
            MachineFamily::Aarch64Virt,
            GuestArchitecture::Aarch64,
            2,
            2048,
            DeviceModel::AppleIntegrated,
            BootPath::AppleVm,
            "uefi_standard",
            staged_disk_artifact_source(),
            None,
            BootDevice::Disk,
        )
        .unwrap_or_else(|error| panic!("{error}"))
    }

    fn stage_guest_kernel_dispatch(
        instance: &mut SoftVmInstance,
        operation: u8,
        kind: u8,
        route: u8,
        arg0: Option<&[u8]>,
        arg1: Option<&[u8]>,
    ) {
        let (arg0_addr, arg0_len) = if let Some(bytes) = arg0 {
            let allocation = instance
                .execution
                .allocate_guest_data(String::from("test:dispatch:arg0"), bytes)
                .unwrap_or_else(|error| panic!("{error}"));
            (allocation.guest_address, allocation.byte_len)
        } else {
            (0, 0)
        };
        let (arg1_addr, arg1_len) = if let Some(bytes) = arg1 {
            let allocation = instance
                .execution
                .allocate_guest_data(String::from("test:dispatch:arg1"), bytes)
                .unwrap_or_else(|error| panic!("{error}"));
            (allocation.guest_address, allocation.byte_len)
        } else {
            (0, 0)
        };
        let request_bytes =
            encode_guest_kernel_request(operation, arg0_addr, arg0_len, arg1_addr, arg1_len);
        let request = instance
            .execution
            .allocate_guest_data(String::from("test:dispatch:request"), &request_bytes)
            .unwrap_or_else(|error| panic!("{error}"));
        instance
            .execution
            .write_register(ISA_REGISTER_ARG0, request.guest_address)
            .unwrap_or_else(|error| panic!("{error}"));
        instance
            .execution
            .write_register(ISA_REGISTER_ARG1, u64::from(kind))
            .unwrap_or_else(|error| panic!("{error}"));
        instance
            .execution
            .write_register(ISA_REGISTER_ARG2, u64::from(route))
            .unwrap_or_else(|error| panic!("{error}"));
        instance
            .execution
            .write_register(ISA_REGISTER_ARG3, u64::from(operation))
            .unwrap_or_else(|error| panic!("{error}"));
        let service_program = instance
            .execution
            .resident_program_named("guest_kernel_service")
            .unwrap_or_else(|error| panic!("{error}"))
            .clone();
        instance.execution.cpu_state.instruction_pointer =
            service_program.entry_point.saturating_add(2);
    }

    fn execute_test_guest_program(
        instance: &mut SoftVmInstance,
        name: &str,
        bytecode: Vec<u8>,
    ) -> SoftVmProgramOutcome {
        let program = instance
            .execution
            .register_resident_program(name, "guest_ram", bytecode)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut control = instance
            .guest_control
            .take()
            .unwrap_or_else(|| panic!("expected guest control state"));
        let outcome = instance
            .execution
            .execute_guest_program(
                &program,
                &instance.spec.machine.guest_architecture,
                instance.spec.machine.vcpu,
                instance.memory.guest_memory_bytes,
                &mut control,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        instance.guest_control = Some(control);
        outcome
    }

    fn single_entry_guest_kernel_service_program(
        entry_point: u64,
        operation: u8,
        kind: u8,
        route: u8,
    ) -> SoftVmResidentProgram {
        let mut bytecode = vec![GUEST_KERNEL_SERVICE_VERSION, 1, operation, kind, route];
        bytecode.extend_from_slice(
            &u64::try_from(2usize.saturating_add(GUEST_KERNEL_SERVICE_DESCRIPTOR_BYTES))
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        SoftVmResidentProgram::new("guest_kernel_service", "guest_ram", entry_point, bytecode)
    }

    fn expected_boot_service_handler(
        machine: &MachineSpec,
        call_id: u8,
        pre_dispatch_mmio_write: Option<(&str, u64)>,
    ) -> Vec<u8> {
        let memory = machine
            .memory_layout()
            .unwrap_or_else(|error| panic!("{error}"));
        let mut bytecode = Vec::new();
        if let Some((device_kind, value)) = pre_dispatch_mmio_write {
            let guest_physical_address = memory
                .topology
                .device_by_kind(device_kind)
                .unwrap_or_else(|| panic!("missing `{device_kind}` device"))
                .guest_physical_base;
            emit_mmio_write64(&mut bytecode, guest_physical_address, value);
        }
        emit_mov_imm64(&mut bytecode, ISA_REGISTER_ARG1, u64::from(call_id));
        emit_native_call(&mut bytecode, NATIVE_CALL_BOOT_SERVICE_ROUTE);
        emit_ret(&mut bytecode);
        bytecode
    }

    fn execute_boot_service_stage(
        instance: &mut SoftVmInstance,
        stage: u8,
    ) -> SoftVmProgramOutcome {
        let boot_service = instance
            .execution
            .resident_program_named("boot_service")
            .unwrap_or_else(|error| panic!("{error}"))
            .clone();
        instance.execution.cpu_state.instruction_pointer =
            boot_service.entry_point.saturating_add(2);
        if let Some(pre_dispatch_mmio_write) = super::boot_service_stage_descriptor(stage)
            .and_then(|descriptor| descriptor.pre_dispatch_mmio_write)
        {
            let guest_physical_address = instance
                .execution
                .machine_topology
                .device_by_kind(pre_dispatch_mmio_write.device_kind)
                .unwrap_or_else(|| {
                    panic!(
                        "missing {} device for boot-stage prelude",
                        pre_dispatch_mmio_write.device_kind
                    )
                })
                .guest_physical_base;
            let _ = instance
                .execution
                .dispatch_mmio_write(guest_physical_address, pre_dispatch_mmio_write.value, None)
                .unwrap_or_else(|error| panic!("{error}"));
        }
        instance
            .execution
            .write_register(ISA_REGISTER_ARG1, u64::from(stage))
            .unwrap_or_else(|error| panic!("{error}"));
        let mut outcome = SoftVmProgramOutcome::default();
        let spec = instance.spec.clone();
        instance
            .execution
            .execute_boot_service_route(&spec, &mut outcome)
            .unwrap_or_else(|error| panic!("{error}"));
        outcome
    }

    #[test]
    fn software_vm_lifecycle_progresses_deterministically() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));
        let heartbeat = instance.heartbeat();
        let witness = instance
            .boot_witness()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(heartbeat.phase, "running");
        assert_eq!(heartbeat.sequence, 1);
        assert_eq!(instance.spec.machine.boot.medium, "firmware");
        assert_eq!(instance.spec.machine.boot_path, "general_purpose");
        assert_eq!(instance.execution.boot_artifacts[0].role, "firmware");
        assert!(
            instance
                .execution
                .resident_programs
                .iter()
                .any(|program| program.name == "boot_dispatch")
        );
        assert_eq!(
            instance
                .execution
                .guest_memory_bytes
                .get(&instance.execution.reset_vector),
            Some(&ISA_OPCODE_CALL_ABS64)
        );
        assert_eq!(witness.boot_device, "disk");
        assert!(witness.guest_control_ready);
        assert!(
            witness
                .console_trace
                .iter()
                .any(|line| line.contains("native executor"))
        );
        assert!(
            instance
                .execution
                .instruction_trace
                .iter()
                .any(|trace| trace.opcode == "firmware_dispatch")
        );
        instance.stop().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(instance.phase.as_str(), "stopped");
    }

    #[test]
    fn software_vm_full_vm_disk_supports_power_cycle_restart() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));

        instance.start().unwrap_or_else(|error| panic!("{error}"));
        let initial_witness = instance
            .boot_witness()
            .unwrap_or_else(|error| panic!("{error}"));
        instance.stop().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(instance.phase.as_str(), "stopped");

        instance.start().unwrap_or_else(|error| panic!("{error}"));
        let rebooted_witness = instance
            .boot_witness()
            .unwrap_or_else(|error| panic!("{error}"));
        let heartbeat = instance.heartbeat();

        assert_eq!(initial_witness.boot_device, "disk");
        assert_eq!(rebooted_witness.boot_device, "disk");
        assert!(rebooted_witness.guest_control_ready);
        assert!(
            rebooted_witness
                .stages
                .iter()
                .any(|stage| stage == "primary_disk:handoff_complete")
        );
        assert_eq!(heartbeat.phase, "running");
        assert!(
            instance
                .guest_control()
                .unwrap_or_else(|error| panic!("{error}"))
                .channels
                .iter()
                .any(|channel| channel.name == "serial" && channel.state == "ready")
        );
    }

    #[test]
    fn resident_program_pages_start_clean_and_executable() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));

        let page = instance
            .execution
            .guest_memory_bytes
            .page(instance.execution.reset_vector)
            .unwrap_or_else(|| panic!("missing resident page"));
        assert!(page.permissions.readable);
        assert!(page.permissions.executable);
        assert!(!page.dirty);
        assert!(page.generation > 0);
    }

    #[test]
    fn guest_stack_writes_mark_pages_dirty_and_advance_generation() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        let stack_address = instance.execution.cpu_state.stack_pointer.saturating_sub(8);

        instance
            .execution
            .push_guest_stack_u64(0x1122_3344_5566_7788)
            .unwrap_or_else(|error| panic!("{error}"));
        let after_push = instance
            .execution
            .guest_memory_bytes
            .page(stack_address)
            .unwrap_or_else(|| panic!("missing stack page after push"));
        assert!(after_push.permissions.writable);
        assert!(after_push.dirty);
        assert!(after_push.generation > 0);

        let generation_after_push = after_push.generation;
        let popped = instance
            .execution
            .pop_guest_stack_u64()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(popped, 0x1122_3344_5566_7788);
        let after_pop = instance
            .execution
            .guest_memory_bytes
            .page(stack_address)
            .unwrap_or_else(|| panic!("missing stack page after pop"));
        assert!(after_pop.dirty);
        assert!(after_pop.generation > generation_after_push);
        assert_eq!(
            instance.execution.guest_memory_bytes.get(&stack_address),
            None
        );
    }

    #[test]
    fn instruction_fetch_requires_execute_permission() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        let allocation = instance
            .execution
            .allocate_guest_data(String::from("data:non_executable"), &[ISA_OPCODE_HALT])
            .unwrap_or_else(|error| panic!("{error}"));

        instance.execution.cpu_state.instruction_pointer = allocation.guest_address;
        let error = instance
            .execution
            .read_instruction_byte()
            .err()
            .unwrap_or_else(|| panic!("expected execute-permission fault"));
        assert!(
            error.message.contains("violates execute permission"),
            "{error}"
        );
        assert_eq!(instance.execution.cpu_state.fault_vector, Some(0x0e));
    }

    #[test]
    fn software_vm_secure_boot_publishes_modeled_measurements() {
        let mut secure_machine = machine();
        secure_machine.boot.firmware_profile = String::from("uefi_secure");
        let spec =
            SoftVmRuntimeSpec::new(ExecutionClass::Balanced, secure_machine).with_secure_boot(true);
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));
        let witness = instance
            .boot_witness()
            .unwrap_or_else(|error| panic!("{error}"));
        let control = instance
            .guest_control()
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(witness.secure_boot_enabled);
        assert!(
            witness
                .stages
                .iter()
                .any(|stage| stage == "secure_boot:policy_enforced")
        );
        assert!(
            witness
                .stages
                .iter()
                .any(|stage| stage == "secure_boot:firmware:measured")
        );
        assert!(
            witness
                .secure_boot_measurements
                .iter()
                .any(|value| value.starts_with("firmware:sha256:"))
        );
        assert!(
            witness
                .secure_boot_measurements
                .iter()
                .any(|value| value.starts_with("primary_disk:sha256:"))
        );
        assert!(witness.console_trace.iter().any(|line| {
            line.contains("Software secure boot policy enforced with firmware profile uefi_secure")
        }));
        assert!(control.files.iter().any(|file| {
            file.path == "/run/uhost/secure-boot/state" && file.contents == "enabled\n"
        }));
        assert!(control.files.iter().any(|file| {
            file.path == "/run/uhost/secure-boot/measurements"
                && file.contents.contains("firmware:sha256:")
        }));
        assert!(
            instance
                .execution
                .completed_events
                .iter()
                .any(|event| event.kind == "secure_boot_policy")
        );
        assert!(
            instance
                .execution
                .completed_events
                .iter()
                .any(|event| event.kind == "secure_boot_measurement")
        );
    }

    #[test]
    fn software_vm_rejects_secure_boot_without_uefi_secure_profile() {
        let spec =
            SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine()).with_secure_boot(true);
        let error = SoftVmInstance::new(spec)
            .err()
            .unwrap_or_else(|| panic!("expected secure-boot firmware-profile rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert_eq!(
            error.message,
            "software secure boot requires firmware_profile `uefi_secure`"
        );
    }

    #[test]
    fn microvm_direct_kernel_stages_kernel_image_and_boot_data() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, microvm_machine());
        let instance = SoftVmInstance::new(spec.clone()).unwrap_or_else(|error| panic!("{error}"));
        let state = instance
            .execution
            .direct_kernel_state()
            .unwrap_or_else(|error| panic!("{error}"))
            .clone();
        let expected_kernel_bytes =
            fs::read(spec.firmware_artifact_source()).unwrap_or_else(|error| panic!("{error}"));
        let expected_preview = expected_kernel_bytes
            .iter()
            .copied()
            .take(usize::try_from(state.preview_byte_len).unwrap_or(usize::MAX))
            .collect::<Vec<_>>();
        let boot_params = String::from_utf8(
            instance
                .execution
                .guest_memory_slice(state.boot_params_guest_address, state.boot_params_byte_len),
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            instance
                .execution
                .guest_memory_slice(state.kernel_entry_guest_address, state.preview_byte_len,),
            expected_preview
        );
        assert_eq!(
            instance.execution.guest_memory_slice(
                state.command_line_guest_address,
                state.command_line_byte_len,
            ),
            state.command_line.as_bytes().to_vec()
        );
        assert!(
            instance
                .execution
                .guest_memory_bytes
                .page(state.kernel_entry_guest_address)
                .unwrap_or_else(|| panic!("missing direct-kernel page"))
                .permissions
                .executable
        );
        assert!(boot_params.contains("boot_path=microvm"));
        assert!(boot_params.contains("kernel_entry=0x"));
        assert!(boot_params.contains("cmdline_addr=0x"));
        assert!(instance.execution.next_program_entry >= 0x0004_0000);
    }

    #[test]
    fn direct_kernel_entry_stage_programs_handoff_registers() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, microvm_machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        let state = instance
            .execution
            .direct_kernel_state()
            .unwrap_or_else(|error| panic!("{error}"))
            .clone();
        let outcome = execute_boot_service_stage(&mut instance, NATIVE_CALL_DIRECT_KERNEL_ENTRY);

        assert_eq!(
            instance
                .execution
                .read_register(ISA_REGISTER_ARG0)
                .unwrap_or_else(|error| panic!("{error}")),
            state.kernel_entry_guest_address
        );
        assert_eq!(
            instance
                .execution
                .read_register(ISA_REGISTER_ARG1)
                .unwrap_or_else(|error| panic!("{error}")),
            state.boot_params_guest_address
        );
        assert_eq!(
            instance
                .execution
                .read_register(ISA_REGISTER_ARG2)
                .unwrap_or_else(|error| panic!("{error}")),
            state.command_line_guest_address
        );
        assert_eq!(
            instance
                .execution
                .read_register(ISA_REGISTER_ARG3)
                .unwrap_or_else(|error| panic!("{error}")),
            state.kernel_byte_len
        );
        assert!(
            outcome
                .stages
                .iter()
                .any(|stage| stage == "direct_kernel:entry_complete")
        );
        assert!(outcome.console_trace.iter().any(|line| {
            line.contains("Direct kernel handoff prepared")
                && line.contains("entry=0x")
                && line.contains("boot_params=0x")
        }));
        assert!(instance.execution.completed_events.iter().any(|event| {
            event.kind == "direct_kernel_entry" && event.detail.contains("boot params")
        }));
    }

    #[test]
    fn microvm_linux_requires_local_kernel_artifact_on_start() {
        let machine = MachineSpec::new(
            MachineFamily::MicrovmLinux,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioMinimal,
            BootPath::MicroVm,
            "object://images/direct-kernel",
            staged_disk_artifact_source(),
            None,
            BootDevice::Disk,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine);
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        let error = instance
            .start()
            .err()
            .unwrap_or_else(|| panic!("expected local-kernel rejection"));

        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert_eq!(
            error.message,
            "software-backed VM execution requires a local absolute path or file:// URI for kernel artifact"
        );
    }

    #[test]
    fn microvm_linux_uses_direct_kernel_boot_flow() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, microvm_machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));
        let witness = instance
            .boot_witness()
            .unwrap_or_else(|error| panic!("{error}"));
        let control = instance
            .guest_control()
            .unwrap_or_else(|error| panic!("{error}"));
        let state = instance
            .execution
            .direct_kernel_state()
            .unwrap_or_else(|error| panic!("{error}"))
            .clone();
        let boot_params = String::from_utf8(
            instance
                .execution
                .guest_memory_slice(state.boot_params_guest_address, state.boot_params_byte_len),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(instance.spec.machine.boot.medium, "direct_kernel");
        assert_eq!(instance.spec.machine.boot_path, "microvm");
        assert_eq!(instance.execution.boot_artifacts[0].role, "kernel");
        assert!(instance.execution.direct_kernel_state.is_some());
        assert!(
            instance
                .execution
                .memory_regions
                .iter()
                .any(|region| region.name == "direct_kernel_image")
        );
        assert!(
            witness
                .stages
                .iter()
                .any(|stage| stage == "direct_kernel:entry_complete")
        );
        assert!(
            witness
                .console_trace
                .iter()
                .any(|line| line.contains("Direct kernel handoff prepared"))
        );
        assert!(
            instance
                .execution
                .instruction_trace
                .iter()
                .any(|trace| trace.opcode == "direct_kernel_entry")
        );
        assert!(control.files.iter().any(|file| {
            file.path == "/proc/cmdline"
                && file.contents == format!("{}\n", direct_kernel_command_line(&instance.spec))
        }));
        assert!(control.files.iter().any(|file| {
            file.path == "/run/uhost/direct-kernel/kernel"
                && file.contents
                    == format!(
                        "{}\n",
                        boot_artifact_display_name(instance.spec.firmware_artifact_source())
                    )
        }));
        assert!(control.files.iter().any(|file| {
            file.path == "/run/uhost/direct-kernel/boot-params"
                && file.contents == boot_params
                && file.contents.contains("boot_path=microvm")
                && file.contents.contains("boot_device=disk")
        }));
        assert!(control.files.iter().any(|file| {
            file.path == "/run/uhost/direct-kernel/handoff"
                && file.contents.contains(&format!(
                    "kernel_entry=0x{:x}",
                    state.kernel_entry_guest_address
                ))
                && file.contents.contains(&format!(
                    "boot_params_addr=0x{:x}",
                    state.boot_params_guest_address
                ))
                && file.contents.contains(&format!(
                    "cmdline_addr=0x{:x}",
                    state.command_line_guest_address
                ))
        }));
    }

    #[test]
    fn microvm_direct_kernel_boot_handoff_consumes_overlay_backed_primary_disk() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, microvm_machine());
        let mut instance =
            SoftVmInstance::new_with_artifact_policy(spec, SoftVmArtifactPolicy::LocalFilesOnly)
                .unwrap_or_else(|error| panic!("{error}"));
        instance
            .execution
            .write_boot_artifact_overlay("primary_disk", 0, b"OVLY")
            .unwrap_or_else(|error| panic!("{error}"));
        let expected_token = padded_le_u64(
            &instance
                .execution
                .read_boot_artifact_range("primary_disk", 0, 8)
                .unwrap_or_else(|error| panic!("{error}")),
        );

        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let block_loop = instance
            .execution
            .device_loops
            .iter()
            .find(|device_loop| device_loop.name == "virt_block_control")
            .unwrap_or_else(|| panic!("expected virt_block_control loop"));
        assert_eq!(
            block_loop.registers.get("last_artifact_role"),
            Some(&BLOCK_CONTROL_ROLE_PRIMARY_DISK)
        );
        assert_eq!(
            block_loop.registers.get("last_transfer_token"),
            Some(&expected_token)
        );
        assert_eq!(block_loop.registers.get("overlay_attached"), Some(&1));
        assert_eq!(block_loop.registers.get("transfer_count"), Some(&1));
        assert_eq!(block_loop.registers.get("responses_ready"), Some(&1));
        assert_eq!(
            block_loop
                .queues
                .iter()
                .find(|queue| queue.name == "requests")
                .unwrap_or_else(|| panic!("expected block request queue"))
                .completed,
            vec![
                u64::from(NATIVE_CALL_BOOT_DEVICE_TRANSFER),
                BLOCK_CONTROL_ROLE_PRIMARY_DISK
            ]
        );
        assert!(instance.execution.mmio_access_log.iter().any(|access| {
            access.region_name == "virt_block_control"
                && access.access_kind == "write"
                && access.value == BLOCK_CONTROL_ROLE_PRIMARY_DISK
                && access.detail == "boot device disk selected for handoff"
        }));
    }

    #[test]
    fn cdrom_boot_produces_installer_witness() {
        let machine = MachineSpec::new(
            MachineFamily::GeneralPurposePci,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioBalanced,
            BootPath::GeneralPurpose,
            "bios",
            staged_disk_artifact_source(),
            Some(staged_install_artifact_source()),
            BootDevice::Cdrom,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine);
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));
        let witness = instance
            .boot_witness()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(witness.boot_device, "cdrom");
        assert!(witness.install_media_attached);
        assert!(
            witness
                .console_trace
                .iter()
                .any(|line| line.contains("installer media preview"))
        );
        assert!(
            witness
                .stages
                .iter()
                .any(|stage| stage == "install_media:manifest_loaded")
        );
    }

    #[test]
    fn boot_service_stage_sequence_tracks_install_media_presence() {
        let disk_spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        assert_eq!(
            boot_service_stage_sequence(&disk_spec),
            vec![
                NATIVE_CALL_FIRMWARE_DISPATCH,
                NATIVE_CALL_BOOT_DEVICE_TRANSFER,
                NATIVE_CALL_USERSPACE_CONTROL,
            ]
        );

        let microvm_spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, microvm_machine());
        assert_eq!(
            boot_service_stage_sequence(&microvm_spec),
            vec![
                NATIVE_CALL_DIRECT_KERNEL_ENTRY,
                NATIVE_CALL_BOOT_DEVICE_TRANSFER,
                NATIVE_CALL_USERSPACE_CONTROL,
            ]
        );

        let cdrom_machine = MachineSpec::new(
            MachineFamily::GeneralPurposePci,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioBalanced,
            BootPath::GeneralPurpose,
            "bios",
            staged_disk_artifact_source(),
            Some(staged_install_artifact_source()),
            BootDevice::Cdrom,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let cdrom_spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, cdrom_machine);
        assert_eq!(
            boot_service_stage_sequence(&cdrom_spec),
            vec![
                NATIVE_CALL_FIRMWARE_DISPATCH,
                NATIVE_CALL_INSTALL_MEDIA_PROBE,
                NATIVE_CALL_BOOT_DEVICE_TRANSFER,
                NATIVE_CALL_USERSPACE_CONTROL,
            ]
        );
    }

    #[test]
    fn boot_service_stage_handlers_preserve_descriptor_driven_preludes() {
        let default_machine = machine();
        assert_eq!(
            build_boot_service_handler(
                &default_machine
                    .memory_layout()
                    .unwrap_or_else(|error| panic!("{error}"))
                    .topology,
                NATIVE_CALL_FIRMWARE_DISPATCH,
            )
            .unwrap_or_else(|error| panic!("{error}")),
            expected_boot_service_handler(&default_machine, NATIVE_CALL_FIRMWARE_DISPATCH, None),
        );
        assert_eq!(
            build_boot_service_handler(
                &default_machine
                    .memory_layout()
                    .unwrap_or_else(|error| panic!("{error}"))
                    .topology,
                NATIVE_CALL_DIRECT_KERNEL_ENTRY,
            )
            .unwrap_or_else(|error| panic!("{error}")),
            expected_boot_service_handler(&default_machine, NATIVE_CALL_DIRECT_KERNEL_ENTRY, None),
        );
        assert_eq!(
            build_boot_service_handler(
                &default_machine
                    .memory_layout()
                    .unwrap_or_else(|error| panic!("{error}"))
                    .topology,
                NATIVE_CALL_INSTALL_MEDIA_PROBE,
            )
            .unwrap_or_else(|error| panic!("{error}")),
            expected_boot_service_handler(
                &default_machine,
                NATIVE_CALL_INSTALL_MEDIA_PROBE,
                Some(("block_control", 1)),
            ),
        );
        assert_eq!(
            build_boot_service_handler(
                &default_machine
                    .memory_layout()
                    .unwrap_or_else(|error| panic!("{error}"))
                    .topology,
                NATIVE_CALL_BOOT_DEVICE_TRANSFER,
            )
            .unwrap_or_else(|error| panic!("{error}")),
            expected_boot_service_handler(
                &default_machine,
                NATIVE_CALL_BOOT_DEVICE_TRANSFER,
                Some(("block_control", u64::from(NATIVE_CALL_BOOT_DEVICE_TRANSFER))),
            ),
        );
        assert_eq!(
            build_boot_service_handler(
                &default_machine
                    .memory_layout()
                    .unwrap_or_else(|error| panic!("{error}"))
                    .topology,
                NATIVE_CALL_USERSPACE_CONTROL,
            )
            .unwrap_or_else(|error| panic!("{error}")),
            expected_boot_service_handler(
                &default_machine,
                NATIVE_CALL_USERSPACE_CONTROL,
                Some(("console", 1)),
            ),
        );
    }

    #[test]
    fn aarch64_topology_drives_boot_service_mmio_preludes() {
        let machine = aarch64_machine();
        let memory = machine
            .memory_layout()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            build_boot_service_handler(&memory.topology, NATIVE_CALL_USERSPACE_CONTROL)
                .unwrap_or_else(|error| panic!("{error}")),
            expected_boot_service_handler(
                &machine,
                NATIVE_CALL_USERSPACE_CONTROL,
                Some(("console", 1)),
            ),
        );
        assert_eq!(
            memory
                .topology
                .device_by_kind("console")
                .unwrap_or_else(|| panic!("missing console device"))
                .guest_physical_base,
            0x0a00_0000
        );
    }

    #[test]
    fn software_vm_aarch64_full_vm_supports_power_cycle_restart() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, aarch64_machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));

        instance.start().unwrap_or_else(|error| panic!("{error}"));
        let initial_witness = instance
            .boot_witness()
            .unwrap_or_else(|error| panic!("{error}"));
        instance.stop().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(instance.phase.as_str(), "stopped");

        instance.start().unwrap_or_else(|error| panic!("{error}"));
        let rebooted_witness = instance
            .boot_witness()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(instance.spec.machine.boot_path, "apple_vm");
        assert_eq!(initial_witness.boot_device, "disk");
        assert_eq!(rebooted_witness.boot_device, "disk");
        assert!(rebooted_witness.guest_control_ready);
        assert!(
            rebooted_witness
                .stages
                .iter()
                .any(|stage| stage == "native_control:ready")
        );
        assert!(
            rebooted_witness
                .console_trace
                .iter()
                .any(|line| { line.contains("Firmware uefi_standard dispatching") })
        );
        assert!(
            instance
                .guest_control()
                .unwrap_or_else(|error| panic!("{error}"))
                .channels
                .iter()
                .any(|channel| channel.name == "guest-agent" && channel.state == "ready")
        );
    }

    #[test]
    fn boot_service_dispatch_route_preserves_boot_device_transfer_semantics() {
        let disk_spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut disk_instance =
            SoftVmInstance::new(disk_spec).unwrap_or_else(|error| panic!("{error}"));
        let expected_disk_token = padded_le_u64(
            &disk_instance
                .execution
                .read_boot_artifact_range("primary_disk", 0, 8)
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let disk_outcome =
            execute_boot_service_stage(&mut disk_instance, NATIVE_CALL_BOOT_DEVICE_TRANSFER);

        assert_eq!(
            disk_outcome.stages,
            vec![String::from("primary_disk:handoff_complete")]
        );
        assert_eq!(
            disk_outcome.console_trace,
            vec![String::from(
                "Primary disk handoff reached guest userspace under native executor",
            )]
        );
        assert!(!disk_outcome.guest_control_ready);
        assert!(
            disk_instance
                .execution
                .completed_events
                .iter()
                .any(|event| {
                    event.kind == "boot_device_transfer"
                        && event.detail == "boot device disk selected for handoff"
                })
        );
        assert!(
            disk_instance
                .execution
                .mmio_access_log
                .iter()
                .any(|access| {
                    access.region_name == "virt_block_control"
                        && access.access_kind == "write"
                        && access.guest_physical_address == 0x1002_0000
                        && access.value == 1
                        && access.detail == "boot device disk selected for handoff"
                })
        );
        let disk_loop = disk_instance
            .execution
            .device_loops
            .iter()
            .find(|device_loop| device_loop.name == "virt_block_control")
            .unwrap_or_else(|| panic!("expected virt_block_control loop"));
        assert_eq!(
            disk_loop.registers.get("last_artifact_role"),
            Some(&BLOCK_CONTROL_ROLE_PRIMARY_DISK)
        );
        assert_eq!(
            disk_loop.registers.get("last_transfer_token"),
            Some(&expected_disk_token)
        );
        assert_eq!(disk_loop.registers.get("transfer_count"), Some(&1));
        assert_eq!(disk_loop.registers.get("overlay_attached"), Some(&1));
        assert_eq!(disk_loop.registers.get("responses_ready"), Some(&1));
        assert_eq!(
            disk_loop
                .queues
                .iter()
                .find(|queue| queue.name == "requests")
                .unwrap_or_else(|| panic!("expected block request queue"))
                .completed,
            vec![
                u64::from(NATIVE_CALL_BOOT_DEVICE_TRANSFER),
                BLOCK_CONTROL_ROLE_PRIMARY_DISK
            ]
        );

        let cdrom_machine = MachineSpec::new(
            MachineFamily::GeneralPurposePci,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioBalanced,
            BootPath::GeneralPurpose,
            "bios",
            staged_disk_artifact_source(),
            Some(staged_install_artifact_source()),
            BootDevice::Cdrom,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let cdrom_spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, cdrom_machine);
        let mut cdrom_instance =
            SoftVmInstance::new(cdrom_spec).unwrap_or_else(|error| panic!("{error}"));
        let expected_cdrom_token = padded_le_u64(
            &cdrom_instance
                .execution
                .read_boot_artifact_range("install_media", 0, 8)
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let cdrom_outcome =
            execute_boot_service_stage(&mut cdrom_instance, NATIVE_CALL_BOOT_DEVICE_TRANSFER);

        assert_eq!(
            cdrom_outcome.stages,
            vec![String::from("installer_environment:ready")]
        );
        assert_eq!(
            cdrom_outcome.console_trace,
            vec![String::from(
                "Installer environment reached control-ready state under native executor",
            )]
        );
        assert!(!cdrom_outcome.guest_control_ready);
        assert!(
            cdrom_instance
                .execution
                .mmio_access_log
                .iter()
                .any(|access| {
                    access.region_name == "virt_block_control"
                        && access.access_kind == "write"
                        && access.guest_physical_address == 0x1002_0000
                        && access.value == 2
                        && access.detail == "boot device cdrom selected for handoff"
                })
        );
        let cdrom_loop = cdrom_instance
            .execution
            .device_loops
            .iter()
            .find(|device_loop| device_loop.name == "virt_block_control")
            .unwrap_or_else(|| panic!("expected virt_block_control loop"));
        assert_eq!(
            cdrom_loop.registers.get("last_artifact_role"),
            Some(&BLOCK_CONTROL_ROLE_INSTALL_MEDIA)
        );
        assert_eq!(
            cdrom_loop.registers.get("last_transfer_token"),
            Some(&expected_cdrom_token)
        );
        assert_eq!(cdrom_loop.registers.get("transfer_count"), Some(&1));
        assert_eq!(cdrom_loop.registers.get("overlay_attached"), Some(&0));
        assert!(
            cdrom_instance
                .execution
                .instruction_trace
                .iter()
                .any(|trace| {
                    trace.program_name == "boot_service"
                        && trace.detail.contains(
                            "boot stage boot_device_transfer executed through boot_service",
                        )
                })
        );
    }

    #[test]
    fn install_media_probe_consumes_block_backed_media_via_block_control() {
        let machine = MachineSpec::new(
            MachineFamily::GeneralPurposePci,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioBalanced,
            BootPath::GeneralPurpose,
            "bios",
            staged_disk_artifact_source(),
            Some(staged_install_artifact_source()),
            BootDevice::Cdrom,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine);
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        let expected_token = padded_le_u64(
            &instance
                .execution
                .read_boot_artifact_range("install_media", 0, 8)
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let _ = execute_boot_service_stage(&mut instance, NATIVE_CALL_INSTALL_MEDIA_PROBE);

        assert!(instance.execution.mmio_access_log.iter().any(|access| {
            access.region_name == "virt_block_control"
                && access.access_kind == "read"
                && access.detail.contains("block control")
        }));
        let block_loop = instance
            .execution
            .device_loops
            .iter()
            .find(|device_loop| device_loop.name == "virt_block_control")
            .unwrap_or_else(|| panic!("expected virt_block_control loop"));
        assert_eq!(
            block_loop.registers.get("last_artifact_role"),
            Some(&BLOCK_CONTROL_ROLE_INSTALL_MEDIA)
        );
        assert_eq!(block_loop.registers.get("probe_count"), Some(&1));
        assert_eq!(block_loop.registers.get("read_count"), Some(&1));
        assert_eq!(
            block_loop.registers.get("last_read_token"),
            Some(&expected_token)
        );
        assert_eq!(block_loop.registers.get("responses_ready"), Some(&0));
        assert_eq!(
            block_loop
                .queues
                .iter()
                .find(|queue| queue.name == "responses")
                .unwrap_or_else(|| panic!("expected block response queue"))
                .completed,
            vec![expected_token]
        );
    }

    #[test]
    fn balanced_softvm_registers_stateful_device_loops() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            instance
                .execution
                .mmio_regions
                .iter()
                .any(|region| region.name == "uart_console")
        );
        assert!(
            instance
                .execution
                .mmio_regions
                .iter()
                .any(|region| region.name == "virt_timer")
        );
        assert!(
            instance
                .execution
                .mmio_regions
                .iter()
                .any(|region| region.name == "virt_block_control")
        );
        assert!(
            instance
                .execution
                .mmio_regions
                .iter()
                .any(|region| region.name == "virtio_console")
        );
        assert!(
            instance
                .execution
                .mmio_regions
                .iter()
                .any(|region| region.name == "virtio_rng")
        );
        assert!(
            instance
                .execution
                .mmio_regions
                .iter()
                .any(|region| region.name == "virtio_net")
        );
        assert!(
            instance
                .execution
                .device_loops
                .iter()
                .any(|device_loop| device_loop.name == "uart_console"
                    && device_loop.device_kind == "serial")
        );
        assert!(
            instance
                .execution
                .device_loops
                .iter()
                .any(|device_loop| device_loop.name == "virt_timer"
                    && device_loop.device_kind == "timer")
        );
        assert!(
            instance
                .execution
                .device_loops
                .iter()
                .any(|device_loop| device_loop.name == "virt_block_control"
                    && device_loop.device_kind == "block_control")
        );
        assert!(
            instance
                .execution
                .device_loops
                .iter()
                .any(|device_loop| device_loop.name == "virtio_console")
        );
        assert!(
            instance
                .execution
                .device_loops
                .iter()
                .any(|device_loop| device_loop.name == "virtio_rng")
        );
        assert!(
            instance
                .execution
                .device_loops
                .iter()
                .any(|device_loop| device_loop.name == "virtio_net")
        );
    }

    #[test]
    fn userspace_control_stage_updates_serial_loop_and_interrupts() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        let outcome = execute_boot_service_stage(&mut instance, NATIVE_CALL_USERSPACE_CONTROL);

        assert_eq!(outcome.stages, vec![String::from("native_control:ready")]);
        let serial_loop = instance
            .execution
            .device_loops
            .iter()
            .find(|device_loop| device_loop.name == "uart_console")
            .unwrap_or_else(|| panic!("expected uart_console loop"));
        assert_eq!(
            serial_loop
                .queues
                .iter()
                .find(|queue| queue.name == "tx")
                .unwrap_or_else(|| panic!("expected serial tx queue"))
                .completed,
            vec![1, 1]
        );
        assert_eq!(serial_loop.registers.get("tx_count"), Some(&2));
        assert!(
            instance
                .execution
                .pending_interrupts
                .iter()
                .any(|interrupt| interrupt.source == "uart_console" && interrupt.vector == 0x24)
        );
    }

    #[test]
    fn virtio_net_mmio_round_trip_updates_queues_and_interrupts() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let mut bytecode = Vec::new();
        emit_mmio_write64(&mut bytecode, 0x1005_0000, 0xfeed_beef);
        emit_mmio_read64(&mut bytecode, ISA_REGISTER_ARG0, 0x1005_0000);
        emit_halt(&mut bytecode);
        let _ = execute_test_guest_program(&mut instance, "virtio_net_probe", bytecode);

        assert_eq!(
            instance
                .execution
                .read_register(ISA_REGISTER_ARG0)
                .unwrap_or_else(|error| panic!("{error}")),
            0xfeed_beef
        );
        let net_loop = instance
            .execution
            .device_loops
            .iter()
            .find(|device_loop| device_loop.name == "virtio_net")
            .unwrap_or_else(|| panic!("expected virtio_net loop"));
        assert_eq!(net_loop.registers.get("tx_packets"), Some(&1));
        assert_eq!(net_loop.registers.get("rx_packets"), Some(&1));
        assert_eq!(
            net_loop
                .queues
                .iter()
                .find(|queue| queue.name == "tx")
                .unwrap_or_else(|| panic!("expected net tx queue"))
                .completed,
            vec![0xfeed_beef]
        );
        assert_eq!(
            net_loop
                .queues
                .iter()
                .find(|queue| queue.name == "rx")
                .unwrap_or_else(|| panic!("expected net rx queue"))
                .completed,
            vec![0xfeed_beef]
        );
        assert!(
            instance
                .execution
                .pending_interrupts
                .iter()
                .any(|interrupt| interrupt.source == "virtio_net" && interrupt.vector == 0x23)
        );
    }

    #[test]
    fn virtio_console_rng_and_timer_mmio_paths_are_stateful() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let mut bytecode = Vec::new();
        emit_mmio_write64(&mut bytecode, 0x1003_0000, 0x41);
        emit_mmio_read64(&mut bytecode, ISA_REGISTER_ARG0, 0x1003_0000);
        emit_mmio_read64(&mut bytecode, ISA_REGISTER_ARG1, 0x1004_0000);
        emit_mmio_write64(&mut bytecode, 0x1001_0000, 0x55);
        emit_mmio_read64(&mut bytecode, ISA_REGISTER_ARG2, 0x1001_0000);
        emit_halt(&mut bytecode);
        let _ =
            execute_test_guest_program(&mut instance, "virtio_console_rng_timer_probe", bytecode);

        assert_eq!(
            instance
                .execution
                .read_register(ISA_REGISTER_ARG0)
                .unwrap_or_else(|error| panic!("{error}")),
            0x41
        );
        assert_eq!(
            instance
                .execution
                .read_register(ISA_REGISTER_ARG1)
                .unwrap_or_else(|error| panic!("{error}")),
            splitmix64(0x9e37_79b9_7f4a_7c15)
        );
        assert_eq!(
            instance
                .execution
                .read_register(ISA_REGISTER_ARG2)
                .unwrap_or_else(|error| panic!("{error}")),
            1
        );
        let console_loop = instance
            .execution
            .device_loops
            .iter()
            .find(|device_loop| device_loop.name == "virtio_console")
            .unwrap_or_else(|| panic!("expected virtio_console loop"));
        assert_eq!(console_loop.registers.get("tx_messages"), Some(&1));
        assert_eq!(console_loop.registers.get("rx_messages"), Some(&1));
        let rng_loop = instance
            .execution
            .device_loops
            .iter()
            .find(|device_loop| device_loop.name == "virtio_rng")
            .unwrap_or_else(|| panic!("expected virtio_rng loop"));
        assert_eq!(rng_loop.registers.get("requests"), Some(&1));
        let timer_loop = instance
            .execution
            .device_loops
            .iter()
            .find(|device_loop| device_loop.name == "virt_timer")
            .unwrap_or_else(|| panic!("expected virt_timer loop"));
        assert_eq!(timer_loop.registers.get("tick_count"), Some(&2));
        assert!(
            instance
                .execution
                .pending_interrupts
                .iter()
                .any(|interrupt| interrupt.source == "virtio_console" && interrupt.vector == 0x25)
        );
        assert!(
            instance
                .execution
                .pending_interrupts
                .iter()
                .any(|interrupt| interrupt.source == "virtio_rng" && interrupt.vector == 0x21)
        );
        assert!(
            instance
                .execution
                .pending_interrupts
                .iter()
                .any(|interrupt| interrupt.source == "virt_timer" && interrupt.vector == 0x20)
        );
    }

    #[test]
    fn uart_console_control_offsets_track_inbound_bytes_and_interrupt_state() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        let serial_base = 0x1000_0000;

        let _ = instance
            .execution
            .dispatch_mmio_write(
                serial_base + DEVICE_MMIO_QUEUE_CONTROL_OFFSET,
                u64::from(b'a'),
                None,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let (status, _) = instance
            .execution
            .dispatch_mmio_read(serial_base + DEVICE_MMIO_STATUS_OFFSET)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status, packed_u32_pair(1, 0));
        let (last_bytes, _) = instance
            .execution
            .dispatch_mmio_read(serial_base + DEVICE_MMIO_QUEUE_CONTROL_OFFSET)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(last_bytes, packed_u32_pair(u64::from(b'a'), 0));
        let (interrupt_state, _) = instance
            .execution
            .dispatch_mmio_read(serial_base + DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            interrupt_state & DEVICE_INTERRUPT_STATE_PENDING,
            DEVICE_INTERRUPT_STATE_PENDING
        );
        let (rx_value, _) = instance
            .execution
            .dispatch_mmio_read(serial_base)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(rx_value, u64::from(b'a'));
        let _ = instance
            .execution
            .dispatch_mmio_write(
                serial_base + DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET,
                DEVICE_INTERRUPT_CONTROL_ACK,
                None,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let (interrupt_state_after, _) = instance
            .execution
            .dispatch_mmio_read(serial_base + DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(interrupt_state_after & DEVICE_INTERRUPT_STATE_PENDING, 0);

        let serial_loop = instance
            .execution
            .device_loops
            .iter()
            .find(|device_loop| device_loop.name == "uart_console")
            .unwrap_or_else(|| panic!("expected uart_console loop"));
        assert_eq!(serial_loop.registers.get("rx_injections"), Some(&1));
        assert_eq!(serial_loop.registers.get("rx_count"), Some(&1));
    }

    #[test]
    fn virtio_net_interrupt_control_replays_latched_work_and_preserves_fifo() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));
        let net_base = 0x1005_0000;

        let _ = instance
            .execution
            .dispatch_mmio_write(
                net_base + DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET,
                DEVICE_INTERRUPT_CONTROL_MASK,
                None,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = instance
            .execution
            .dispatch_mmio_write(net_base, 0x11, None)
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = instance
            .execution
            .dispatch_mmio_write(net_base, 0x22, None)
            .unwrap_or_else(|error| panic!("{error}"));

        let (status, _) = instance
            .execution
            .dispatch_mmio_read(net_base + DEVICE_MMIO_STATUS_OFFSET)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status, packed_u32_pair(2, 2));
        let (interrupt_state, _) = instance
            .execution
            .dispatch_mmio_read(net_base + DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            interrupt_state & DEVICE_INTERRUPT_STATE_MASKED,
            DEVICE_INTERRUPT_STATE_MASKED
        );
        assert_eq!(
            interrupt_state & DEVICE_INTERRUPT_STATE_LATCHED,
            DEVICE_INTERRUPT_STATE_LATCHED
        );
        assert_eq!(
            instance
                .execution
                .pending_interrupts
                .iter()
                .filter(|interrupt| interrupt.source == "virtio_net")
                .count(),
            0
        );

        let _ = instance
            .execution
            .dispatch_mmio_write(
                net_base + DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET,
                DEVICE_INTERRUPT_CONTROL_UNMASK,
                None,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            instance
                .execution
                .pending_interrupts
                .iter()
                .filter(|interrupt| interrupt.source == "virtio_net")
                .count(),
            1
        );

        let _ = instance
            .execution
            .dispatch_mmio_write(
                net_base + DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET,
                DEVICE_INTERRUPT_CONTROL_ACK,
                None,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            instance
                .execution
                .pending_interrupts
                .iter()
                .filter(|interrupt| interrupt.source == "virtio_net")
                .count(),
            1
        );

        let (first_packet, _) = instance
            .execution
            .dispatch_mmio_read(net_base)
            .unwrap_or_else(|error| panic!("{error}"));
        let (second_packet, _) = instance
            .execution
            .dispatch_mmio_read(net_base)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!((first_packet, second_packet), (0x11, 0x22));

        let (status_after, _) = instance
            .execution
            .dispatch_mmio_read(net_base + DEVICE_MMIO_STATUS_OFFSET)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status_after, packed_u32_pair(0, 2));

        let _ = instance
            .execution
            .dispatch_mmio_write(
                net_base + DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET,
                DEVICE_INTERRUPT_CONTROL_ACK,
                None,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let (interrupt_state_after, _) = instance
            .execution
            .dispatch_mmio_read(net_base + DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(interrupt_state_after & DEVICE_INTERRUPT_STATE_PENDING, 0);

        let net_loop = instance
            .execution
            .device_loops
            .iter()
            .find(|device_loop| device_loop.name == "virtio_net")
            .unwrap_or_else(|| panic!("expected virtio_net loop"));
        assert_eq!(net_loop.registers.get("tx_packets"), Some(&2));
        assert_eq!(net_loop.registers.get("rx_packets"), Some(&2));
        assert_eq!(net_loop.registers.get("interrupt_ack_count"), Some(&2));
    }

    #[test]
    fn virt_timer_control_offsets_accumulate_edge_interrupts() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        let timer_base = 0x1001_0000;

        let _ = instance
            .execution
            .dispatch_mmio_write(timer_base, 0x10, None)
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = instance
            .execution
            .dispatch_mmio_write(timer_base + DEVICE_MMIO_QUEUE_CONTROL_OFFSET, 0x20, None)
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            instance
                .execution
                .pending_interrupts
                .iter()
                .filter(|interrupt| interrupt.source == "virt_timer")
                .count(),
            2
        );
        let (status, _) = instance
            .execution
            .dispatch_mmio_read(timer_base + DEVICE_MMIO_STATUS_OFFSET)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status, packed_u32_pair(2, 2));
        let (last_deadline, _) = instance
            .execution
            .dispatch_mmio_read(timer_base + DEVICE_MMIO_QUEUE_CONTROL_OFFSET)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(last_deadline, 0x20);

        let _ = instance
            .execution
            .dispatch_mmio_write(
                timer_base + DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET,
                DEVICE_INTERRUPT_CONTROL_ACK,
                None,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            instance
                .execution
                .pending_interrupts
                .iter()
                .filter(|interrupt| interrupt.source == "virt_timer")
                .count(),
            0
        );

        let timer_loop = instance
            .execution
            .device_loops
            .iter()
            .find(|device_loop| device_loop.name == "virt_timer")
            .unwrap_or_else(|| panic!("expected virt_timer loop"));
        assert_eq!(timer_loop.registers.get("tick_count"), Some(&2));
        assert_eq!(timer_loop.registers.get("backend_ticks"), Some(&1));
        assert_eq!(
            timer_loop
                .queues
                .iter()
                .find(|queue| queue.name == "events")
                .unwrap_or_else(|| panic!("expected timer event queue"))
                .completed,
            vec![0x10, 0x20]
        );
    }

    #[test]
    fn microvm_block_control_queue_offset_reads_follow_up_blocks_from_disk_substrate() {
        let block_size =
            usize::try_from(DEFAULT_BLOCK_SIZE_BYTES).unwrap_or_else(|error| panic!("{error}"));
        let mut disk_bytes = vec![0u8; block_size * 2];
        disk_bytes[..8].copy_from_slice(b"blkzero!");
        disk_bytes[block_size..block_size + 8].copy_from_slice(b"blkone!!");
        let disk_source = staged_artifact_path("microvm-two-block-disk.raw", &disk_bytes);
        let machine = MachineSpec::new(
            MachineFamily::MicrovmLinux,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioMinimal,
            BootPath::MicroVm,
            staged_kernel_artifact_source(),
            disk_source,
            None,
            BootDevice::Disk,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine);
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let block_base = 0x1000_2000;
        let (first_token, _) = instance
            .execution
            .dispatch_mmio_read(block_base)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first_token, padded_le_u64(b"blkzero!"));
        let _ = instance
            .execution
            .dispatch_mmio_write(
                block_base + DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET,
                DEVICE_INTERRUPT_CONTROL_ACK,
                None,
            )
            .unwrap_or_else(|error| panic!("{error}"));

        let _ = instance
            .execution
            .dispatch_mmio_write(block_base + DEVICE_MMIO_QUEUE_CONTROL_OFFSET, 1, None)
            .unwrap_or_else(|error| panic!("{error}"));
        let (status, _) = instance
            .execution
            .dispatch_mmio_read(block_base + DEVICE_MMIO_STATUS_OFFSET)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(status, packed_u32_pair(1, 1));
        let (cursor, _) = instance
            .execution
            .dispatch_mmio_read(block_base + DEVICE_MMIO_QUEUE_CONTROL_OFFSET)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(cursor, packed_u32_pair(1, 2));
        let (artifact_bytes, _) = instance
            .execution
            .dispatch_mmio_read(block_base + DEVICE_MMIO_METADATA_OFFSET)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            artifact_bytes,
            u64::try_from(disk_bytes.len()).unwrap_or(u64::MAX)
        );
        let (second_token, _) = instance
            .execution
            .dispatch_mmio_read(block_base)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second_token, padded_le_u64(b"blkone!!"));

        let block_loop = instance
            .execution
            .device_loops
            .iter()
            .find(|device_loop| device_loop.name == "virt_block_control")
            .unwrap_or_else(|| panic!("expected virt_block_control loop"));
        assert_eq!(block_loop.registers.get("block_request_count"), Some(&1));
        assert_eq!(block_loop.registers.get("last_block_index"), Some(&1));
        assert_eq!(
            block_loop
                .queues
                .iter()
                .find(|queue| queue.name == "requests")
                .unwrap_or_else(|| panic!("expected block request queue"))
                .completed
                .last(),
            Some(&1)
        );

        let _ = instance
            .execution
            .dispatch_mmio_write(
                block_base + DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET,
                DEVICE_INTERRUPT_CONTROL_ACK,
                None,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let (interrupt_state_after, _) = instance
            .execution
            .dispatch_mmio_read(block_base + DEVICE_MMIO_INTERRUPT_CONTROL_OFFSET)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(interrupt_state_after & DEVICE_INTERRUPT_STATE_PENDING, 0);
    }

    #[test]
    fn guest_kernel_route_descriptors_cover_declared_operations() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        for entry in GUEST_KERNEL_SERVICE_ENTRIES.iter().copied() {
            let descriptor = guest_kernel_service_descriptor(&instance.execution, entry.operation)
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(descriptor.operation.kind, entry.kind);
            assert_eq!(descriptor.operation.route, entry.route);
            let route_descriptor = guest_kernel_route_descriptor(entry.route)
                .unwrap_or_else(|| panic!("missing route descriptor for route {}", entry.route));
            assert_eq!(route_descriptor.route, entry.route);
        }
    }

    #[test]
    fn guest_kernel_dispatch_route_preserves_file_read_semantics() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let mut control = instance
            .guest_control
            .take()
            .unwrap_or_else(|| panic!("expected guest control state"));
        stage_guest_kernel_dispatch(
            &mut instance,
            NATIVE_CALL_GUEST_CAT,
            GUEST_KERNEL_SERVICE_KIND_READ_ONLY,
            GUEST_KERNEL_ROUTE_FILE_READ,
            Some(b"/proc/sys/kernel/uname"),
            None,
        );

        instance
            .execution
            .execute_guest_kernel_service_route(
                &mut control,
                instance.spec.machine.vcpu,
                instance.memory.guest_memory_bytes,
            )
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            read_guest_file(&instance.execution, &control, "/run/guest-kernel/operation")
                .unwrap_or_else(|| panic!("expected guest-kernel operation file")),
            "guest_cat\n"
        );
        assert_eq!(
            read_guest_file(&instance.execution, &control, "/run/guest-kernel/exit-code")
                .unwrap_or_else(|| panic!("expected guest-kernel exit-code file")),
            "0\n"
        );
        assert!(
            read_guest_file(&instance.execution, &control, "/run/guest-kernel/stdout")
                .unwrap_or_else(|| panic!("expected guest-kernel stdout file"))
                .contains("Linux uvm-native-x86_64")
        );
        assert!(instance.execution.instruction_trace.iter().any(|trace| {
            trace.program_name == "guest_kernel_service"
                && trace
                    .detail
                    .contains("guest-kernel route guest_cat executed via read_only")
        }));
    }

    #[test]
    fn guest_kernel_dispatch_lookup_route_reads_materialized_service_status_file() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let mut control = instance
            .guest_control
            .take()
            .unwrap_or_else(|| panic!("expected guest control state"));
        stage_guest_kernel_dispatch(
            &mut instance,
            NATIVE_CALL_GUEST_SYSTEMCTL_STATUS,
            GUEST_KERNEL_SERVICE_KIND_READ_ONLY,
            GUEST_KERNEL_ROUTE_SERVICE_STATUS,
            Some(b"guest-control"),
            None,
        );

        instance
            .execution
            .execute_guest_kernel_service_route(
                &mut control,
                instance.spec.machine.vcpu,
                instance.memory.guest_memory_bytes,
            )
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            read_guest_file(&instance.execution, &control, "/run/guest-kernel/exit-code")
                .unwrap_or_else(|| panic!("expected guest-kernel exit-code file")),
            "0\n"
        );
        let stdout = read_guest_file(&instance.execution, &control, "/run/guest-kernel/stdout")
            .unwrap_or_else(|| panic!("expected guest-kernel stdout file"));
        assert!(stdout.contains("● guest-control.service - UVM native synthetic service"));
        assert!(stdout.contains("Active: running"));
    }

    #[test]
    fn guest_kernel_dispatch_lookup_route_preserves_missing_service_status_semantics() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let mut control = instance
            .guest_control
            .take()
            .unwrap_or_else(|| panic!("expected guest control state"));
        stage_guest_kernel_dispatch(
            &mut instance,
            NATIVE_CALL_GUEST_SYSTEMCTL_STATUS,
            GUEST_KERNEL_SERVICE_KIND_READ_ONLY,
            GUEST_KERNEL_ROUTE_SERVICE_STATUS,
            Some(b"missing-daemon"),
            None,
        );

        instance
            .execution
            .execute_guest_kernel_service_route(
                &mut control,
                instance.spec.machine.vcpu,
                instance.memory.guest_memory_bytes,
            )
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            read_guest_file(&instance.execution, &control, "/run/guest-kernel/exit-code")
                .unwrap_or_else(|| panic!("expected guest-kernel exit-code file")),
            "4\n"
        );
        assert_eq!(
            read_guest_file(&instance.execution, &control, "/run/guest-kernel/stderr")
                .unwrap_or_else(|| panic!("expected guest-kernel stderr file")),
            "Unit missing-daemon.service could not be found.\n"
        );
    }

    #[test]
    fn guest_kernel_dispatch_lookup_route_treats_empty_directory_index_as_missing() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let mut control = instance
            .guest_control
            .take()
            .unwrap_or_else(|| panic!("expected guest control state"));
        upsert_guest_file_raw(
            &mut instance.execution,
            &mut control.files,
            guest_directory_index_path("/var/empty"),
            String::new(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        stage_guest_kernel_dispatch(
            &mut instance,
            NATIVE_CALL_GUEST_LS,
            GUEST_KERNEL_SERVICE_KIND_INDEX,
            GUEST_KERNEL_ROUTE_DIRECTORY_INDEX,
            Some(b"/var/empty"),
            None,
        );

        instance
            .execution
            .execute_guest_kernel_service_route(
                &mut control,
                instance.spec.machine.vcpu,
                instance.memory.guest_memory_bytes,
            )
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            read_guest_file(&instance.execution, &control, "/run/guest-kernel/exit-code")
                .unwrap_or_else(|| panic!("expected guest-kernel exit-code file")),
            "2\n"
        );
        assert_eq!(
            read_guest_file(&instance.execution, &control, "/run/guest-kernel/stderr")
                .unwrap_or_else(|| panic!("expected guest-kernel stderr file")),
            "ls: cannot access '/var/empty': No such file or directory\n"
        );
        assert_eq!(
            read_guest_file(&instance.execution, &control, "/run/guest-kernel/stdout")
                .unwrap_or_else(|| panic!("expected guest-kernel stdout file")),
            ""
        );
    }

    #[test]
    fn guest_file_projection_batch_refreshes_directory_and_digest_metadata() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let mut control = instance
            .guest_control
            .take()
            .unwrap_or_else(|| panic!("expected guest control state"));
        upsert_guest_file_batch(
            &mut instance.execution,
            &mut control.files,
            [
                GuestFileProjection::new("/opt/metadata/batch-one", "alpha\n"),
                GuestFileProjection::new("/opt/metadata/batch-two", "beta\n"),
            ],
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            read_guest_file(
                &instance.execution,
                &control,
                &guest_directory_index_path("/opt/metadata"),
            )
            .unwrap_or_else(|| panic!("expected /opt/metadata directory index")),
            "batch-one\nbatch-two\n"
        );
        assert_eq!(
            read_guest_file(
                &instance.execution,
                &control,
                &guest_sha256_index_path("/opt/metadata/batch-two"),
            )
            .unwrap_or_else(|| panic!("expected /opt/metadata/batch-two digest index")),
            format!("{}  /opt/metadata/batch-two\n", sha256_hex(b"beta\n"))
        );
    }

    #[test]
    fn guest_kernel_dispatch_rejects_register_descriptor_mismatch() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let mut control = instance
            .guest_control
            .take()
            .unwrap_or_else(|| panic!("expected guest control state"));
        stage_guest_kernel_dispatch(
            &mut instance,
            NATIVE_CALL_GUEST_CAT,
            GUEST_KERNEL_SERVICE_KIND_READ_ONLY,
            GUEST_KERNEL_ROUTE_FILE_TOUCH,
            Some(b"/proc/sys/kernel/uname"),
            None,
        );

        let error = instance
            .execution
            .execute_guest_kernel_service_route(
                &mut control,
                instance.spec.machine.vcpu,
                instance.memory.guest_memory_bytes,
            )
            .err()
            .unwrap_or_else(|| panic!("expected guest-kernel descriptor mismatch"));

        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert_eq!(
            error.message,
            "guest-kernel service registers do not match descriptor"
        );
        assert!(!instance.execution.cpu_state.faulted);
    }

    #[test]
    fn guest_kernel_dispatch_faults_on_unsupported_route_descriptor() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let mut control = instance
            .guest_control
            .take()
            .unwrap_or_else(|| panic!("expected guest control state"));
        let service_entry_point = instance
            .execution
            .resident_program_named("guest_kernel_service")
            .unwrap_or_else(|error| panic!("{error}"))
            .entry_point;
        let unsupported_program = single_entry_guest_kernel_service_program(
            service_entry_point,
            NATIVE_CALL_GUEST_CAT,
            GUEST_KERNEL_SERVICE_KIND_READ_ONLY,
            0xfe,
        );
        let service_index = instance
            .execution
            .resident_programs
            .iter()
            .position(|program| program.name == "guest_kernel_service")
            .unwrap_or_else(|| panic!("expected guest_kernel_service resident program"));
        instance.execution.resident_programs[service_index] = unsupported_program;
        stage_guest_kernel_dispatch(
            &mut instance,
            NATIVE_CALL_GUEST_CAT,
            GUEST_KERNEL_SERVICE_KIND_READ_ONLY,
            0xfe,
            Some(b"/proc/sys/kernel/uname"),
            None,
        );

        let error = instance
            .execution
            .execute_guest_kernel_service_route(
                &mut control,
                instance.spec.machine.vcpu,
                instance.memory.guest_memory_bytes,
            )
            .err()
            .unwrap_or_else(|| panic!("expected unsupported guest-kernel route fault"));

        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
        assert!(instance.execution.cpu_state.faulted);
        assert_eq!(instance.execution.cpu_state.fault_vector, Some(0x0d));
        assert!(
            instance
                .execution
                .cpu_state
                .fault_detail
                .as_deref()
                .is_some_and(|detail| detail.contains("unsupported guest-kernel service route"))
        );
        assert!(instance.execution.instruction_trace.iter().any(|trace| {
            trace.program_name == "guest_kernel_service"
                && trace
                    .detail
                    .contains("guest-kernel route guest_cat executed via read_only")
        }));
        assert!(
            instance
                .execution
                .pending_interrupts
                .iter()
                .any(|interrupt| { interrupt.source == "cpu_fault" && interrupt.vector == 0x0d })
        );
    }

    #[test]
    fn guest_control_commands_are_stateful() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let write = instance
            .run_guest_command("echo benchmark-start > /var/tmp/workload-state")
            .unwrap_or_else(|error| panic!("{error}"));
        let cat = instance
            .run_guest_command("cat /var/tmp/workload-state")
            .unwrap_or_else(|error| panic!("{error}"));
        let listing = instance
            .run_guest_command("ls /var/tmp")
            .unwrap_or_else(|error| panic!("{error}"));
        let digest = instance
            .run_guest_command("sha256sum /var/tmp/workload-state")
            .unwrap_or_else(|error| panic!("{error}"));
        let control = instance
            .guest_control()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(write.exit_code, 0);
        assert_eq!(write.channel, "serial");
        assert_eq!(write.execution_semantics, "interpreted_guest_isa_v0");
        assert_eq!(write.instruction_count, 7);
        assert_eq!(cat.stdout, "benchmark-start\n");
        assert!(listing.stdout.lines().any(|line| line == "workload-state"));
        assert!(digest.stdout.contains("/var/tmp/workload-state"));
        assert!(instance.execution.instruction_trace.iter().any(|trace| {
            trace.program_name == "guest_kernel_service"
                && trace.opcode == "guest_service_route_dispatch"
        }));
        assert_eq!(instance.execution.cpu_state.last_trap_vector, Some(0x20));
        assert!(
            instance
                .execution
                .pending_interrupts
                .iter()
                .any(|interrupt| interrupt.source == "virt_timer")
        );
        assert!(control.files.iter().any(|file| {
            file.path == "/var/tmp/workload-state"
                && file.contents == "benchmark-start\n"
                && file.resident_guest_address >= GUEST_RAM_DATA_BASE
                && file.resident_byte_len == 16
        }));
        assert!(control.channels.iter().any(|channel| {
            channel.name == "serial"
                && channel.state == "ready"
                && channel.tx_count == 4
                && channel.rx_count == 4
                && channel.last_command.as_deref() == Some("sha256sum /var/tmp/workload-state")
                && channel.last_exit_code == Some(0)
        }));
        assert_eq!(control.history.len(), 4);
    }

    #[test]
    fn guest_control_exposes_default_ingress_web_root() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let control = instance
            .guest_control()
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(
            control
                .services
                .iter()
                .any(|service| service.name == "ingress-relay" && service.state == "running")
        );
        assert_eq!(
            read_guest_file(
                &instance.execution,
                &control,
                "/run/guest-ingress/transport",
            )
            .unwrap_or_else(|| panic!("expected guest ingress transport file")),
            format!("{}\n", super::GUEST_INGRESS_TRANSPORT)
        );
        assert_eq!(
            read_guest_file(&instance.execution, &control, "/run/guest-ingress/web-root",)
                .unwrap_or_else(|| panic!("expected guest ingress web-root file")),
            format!("{}\n", super::GUEST_INGRESS_WEB_ROOT)
        );
        let index = read_guest_file(&instance.execution, &control, "/var/www/index.html")
            .unwrap_or_else(|| panic!("expected guest ingress index file"));
        assert!(index.contains("Managed ingress is live."));
        assert_eq!(
            read_guest_file(&instance.execution, &control, "/var/www/healthz")
                .unwrap_or_else(|| panic!("expected guest ingress healthz file")),
            "ok\n"
        );
    }

    #[test]
    fn guest_control_exposes_guest_owned_network_state() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let ip_addr = instance
            .run_guest_command("ip addr")
            .unwrap_or_else(|error| panic!("{error}"));
        let ip_route = instance
            .run_guest_command("ip route")
            .unwrap_or_else(|error| panic!("{error}"));
        let resolvectl = instance
            .run_guest_command("resolvectl status")
            .unwrap_or_else(|error| panic!("{error}"));
        let listeners = instance
            .run_guest_command("ss -ltn")
            .unwrap_or_else(|error| panic!("{error}"));
        let control = instance
            .guest_control()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(ip_addr.exit_code, 0);
        assert!(ip_addr.stdout.contains("eth0"));
        assert!(ip_addr.stdout.contains("10.0.2.15/24"));
        assert_eq!(ip_route.exit_code, 0);
        assert!(ip_route.stdout.contains("default via 10.0.2.2"));
        assert!(resolvectl.stdout.contains("10.0.2.3"));
        assert!(listeners.stdout.contains("127.0.0.1:0"));
        assert!(
            control
                .services
                .iter()
                .any(|service| service.name == "dns-relay" && service.state == "running")
        );
        assert_eq!(
            read_guest_file(&instance.execution, &control, "/run/guest-network/mode")
                .unwrap_or_else(|| panic!("expected guest network mode file")),
            "guest_owned_usernet_nat\n"
        );
        assert_eq!(
            read_guest_file(&instance.execution, &control, "/etc/resolv.conf")
                .unwrap_or_else(|| panic!("expected guest resolv.conf")),
            "# UHost managed guest resolver for uvm-native-x86_64\nnameserver 10.0.2.3\nsearch uhost.internal\n"
        );
    }

    #[test]
    fn guest_control_http_fetch_relays_body_and_persists_egress_state() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let url = spawn_http_probe_server(
            "HTTP/1.1 200 OK",
            &[("Content-Type", "text/plain; charset=utf-8")],
            "hello from egress\n",
        );
        let result = instance
            .run_guest_command(&format!("curl {url}"))
            .unwrap_or_else(|error| panic!("{error}"));
        let control = instance
            .guest_control()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "hello from egress\n");
        assert_eq!(result.stderr, "");
        assert!(
            control
                .services
                .iter()
                .any(|service| { service.name == "egress-relay" && service.state == "running" })
        );
        assert_eq!(
            read_guest_file(&instance.execution, &control, "/run/guest-egress/last-url")
                .unwrap_or_else(|| panic!("expected guest egress last-url file")),
            format!("{url}\n")
        );
        assert_eq!(
            read_guest_file(
                &instance.execution,
                &control,
                "/run/guest-egress/last-method",
            )
            .unwrap_or_else(|| panic!("expected guest egress last-method file")),
            "GET\n"
        );
        assert_eq!(
            read_guest_file(
                &instance.execution,
                &control,
                "/run/guest-egress/last-status-line",
            )
            .unwrap_or_else(|| panic!("expected guest egress last-status-line file")),
            "HTTP/1.1 200 OK\n"
        );
        assert_eq!(
            read_guest_file(
                &instance.execution,
                &control,
                "/var/log/guest-egress/last-body",
            )
            .unwrap_or_else(|| panic!("expected guest egress last-body file")),
            "hello from egress\n"
        );
    }

    #[test]
    fn guest_control_http_fetch_head_returns_headers_without_body() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let url = spawn_http_probe_server(
            "HTTP/1.1 204 No Content",
            &[("Content-Type", "text/plain")],
            "",
        );
        let result = instance
            .run_guest_command(&format!("curl -I {url}"))
            .unwrap_or_else(|error| panic!("{error}"));
        let control = instance
            .guest_control()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("HTTP/1.1 204 No Content"));
        assert_eq!(result.stderr, "");
        assert_eq!(
            read_guest_file(
                &instance.execution,
                &control,
                "/run/guest-egress/last-method",
            )
            .unwrap_or_else(|| panic!("expected guest egress last-method file")),
            "HEAD\n"
        );
        assert_eq!(
            read_guest_file(
                &instance.execution,
                &control,
                "/var/log/guest-egress/last-body",
            )
            .unwrap_or_else(|| panic!("expected guest egress last-body file")),
            ""
        );
    }

    #[test]
    fn guest_control_tcp_connect_relays_payload_and_persists_state() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let target = spawn_tcp_probe_server("hello from tcp\n");
        let target_command = target.replace(':', " ");
        let result = instance
            .run_guest_command(&format!("nc {target_command} ping-from-guest"))
            .unwrap_or_else(|error| panic!("{error}"));
        let control = instance
            .guest_control()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "hello from tcp\n");
        assert_eq!(result.stderr, "");
        assert!(
            control
                .services
                .iter()
                .any(|service| service.name == "tcp-egress-relay" && service.state == "running")
        );
        assert_eq!(
            read_guest_file(&instance.execution, &control, "/run/guest-tcp/last-target")
                .unwrap_or_else(|| panic!("expected guest tcp last-target file")),
            format!("{target}\n")
        );
        assert_eq!(
            read_guest_file(&instance.execution, &control, "/run/guest-tcp/last-probe")
                .unwrap_or_else(|| panic!("expected guest tcp last-probe file")),
            "false\n"
        );
        assert_eq!(
            read_guest_file(
                &instance.execution,
                &control,
                "/var/log/guest-tcp/last-received",
            )
            .unwrap_or_else(|| panic!("expected guest tcp receive log")),
            "hello from tcp\n"
        );
    }

    #[test]
    fn guest_control_udp_exchange_relays_payload_and_persists_state() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let target = spawn_udp_probe_server("hello from udp\n");
        let target_command = target.replace(':', " ");
        let result = instance
            .run_guest_command(&format!("nc -u {target_command} ping-from-guest"))
            .unwrap_or_else(|error| panic!("{error}"));
        let control = instance
            .guest_control()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "hello from udp\n");
        assert_eq!(result.stderr, "");
        assert!(
            control
                .services
                .iter()
                .any(|service| service.name == "udp-egress-relay" && service.state == "running")
        );
        assert_eq!(
            read_guest_file(&instance.execution, &control, "/run/guest-udp/last-target")
                .unwrap_or_else(|| panic!("expected guest udp last-target file")),
            format!("{target}\n")
        );
        assert_eq!(
            read_guest_file(
                &instance.execution,
                &control,
                "/var/log/guest-udp/last-received"
            )
            .unwrap_or_else(|| panic!("expected guest udp receive log")),
            "hello from udp\n"
        );
    }

    #[test]
    fn guest_control_dns_lookup_resolves_hostnames() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let result = instance
            .run_guest_command("nslookup localhost")
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("Server:"));
        assert!(result.stdout.contains("Name:\tlocalhost"));
        assert!(result.stdout.contains("Address:"));
    }

    #[test]
    fn unixbench_command_persists_guest_artifacts() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let summary = instance
            .run_guest_command("unixbench --summary")
            .unwrap_or_else(|error| panic!("{error}"));
        let latest = instance
            .run_guest_command("cat /var/log/unixbench/latest.log")
            .unwrap_or_else(|error| panic!("{error}"));
        let control = instance
            .guest_control()
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(summary.stdout.contains("Measurement source:"));
        assert!(summary.stdout.contains("System Benchmarks Index Score"));
        assert_eq!(summary.channel, "serial");
        assert_eq!(summary.execution_semantics, "interpreted_guest_isa_v0");
        assert_eq!(summary.instruction_count, 7);
        assert_eq!(latest.stdout, summary.stdout);
        assert_eq!(control.benchmark_runs, 1);
        assert!(control.files.iter().any(|file| {
            file.path == "/var/log/unixbench/latest.log"
                && file.resident_guest_address >= GUEST_RAM_DATA_BASE
                && file.resident_byte_len > 0
        }));
        assert!(
            control
                .files
                .iter()
                .any(|file| file.path == "/var/lib/unixbench/metrics/source")
        );
        assert!(
            control
                .files
                .iter()
                .any(|file| file.path == "/var/tmp/unixbench-score")
        );
    }

    #[test]
    fn guest_control_supports_serial_virtio_console_and_guest_agent_command_paths() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let serial = instance
            .run_guest_command("serial::uname -a")
            .unwrap_or_else(|error| panic!("{error}"));
        let virtio = instance
            .run_guest_command("virtio-console::cat /etc/hostname")
            .unwrap_or_else(|error| panic!("{error}"));
        let agent = instance
            .run_guest_command("guest-agent::systemctl is-system-running")
            .unwrap_or_else(|error| panic!("{error}"));
        let control = instance
            .guest_control()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(serial.channel, "serial");
        assert_eq!(virtio.channel, "virtio-console");
        assert_eq!(virtio.stdout, format!("{}\n", control.hostname));
        assert_eq!(agent.channel, "guest-agent");
        assert_eq!(agent.stdout, "running\n");
        assert!(control.channels.iter().any(|channel| {
            channel.name == "serial"
                && channel.delivery_path == "uart_console"
                && channel.tx_count == 1
                && channel.rx_count == 1
                && channel.last_command.as_deref() == Some("uname -a")
                && channel.last_exit_code == Some(0)
        }));
        assert!(control.channels.iter().any(|channel| {
            channel.name == "virtio-console"
                && channel.delivery_path == "virtio_console"
                && channel.tx_count == 1
                && channel.rx_count == 1
                && channel.last_command.as_deref() == Some("cat /etc/hostname")
                && channel.last_exit_code == Some(0)
        }));
        assert!(control.channels.iter().any(|channel| {
            channel.name == "guest-agent"
                && channel.delivery_path == "guest_agent_rpc"
                && channel.tx_count == 1
                && channel.rx_count == 1
                && channel.last_command.as_deref() == Some("systemctl is-system-running")
                && channel.last_exit_code == Some(0)
        }));
        assert_eq!(
            read_guest_file(&instance.execution, &control, "/run/guest-kernel/stdout")
                .unwrap_or_else(|| panic!("expected guest-kernel stdout file")),
            agent.stdout
        );
        assert!(instance.execution.mmio_access_log.iter().any(|access| {
            access.region_name == "uart_console"
                && access.detail.contains("serial guest command dispatched")
        }));
        assert!(instance.execution.mmio_access_log.iter().any(|access| {
            access.region_name == "virtio_console"
                && access
                    .detail
                    .contains("virtio-console guest command dispatched")
        }));
        assert!(
            instance
                .execution
                .completed_events
                .iter()
                .any(|event| event.kind == "guest_agent_dispatch")
        );
    }

    #[test]
    fn guest_command_execution_rebuilds_stale_channel_mirror_before_dispatch() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let mut control = instance
            .guest_control
            .take()
            .unwrap_or_else(|| panic!("expected guest control state"));
        control.channels.clear();
        instance.guest_control = Some(control);

        let serial = instance
            .run_guest_command("serial::uname -a")
            .unwrap_or_else(|error| panic!("{error}"));
        let virtio = instance
            .run_guest_command("virtio-console::cat /etc/hostname")
            .unwrap_or_else(|error| panic!("{error}"));
        let control = instance
            .guest_control()
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(serial.channel, "serial");
        assert_eq!(virtio.channel, "virtio-console");
        assert!(control.channels.iter().any(|channel| {
            channel.name == "serial"
                && channel.state == "ready"
                && channel.tx_count == 1
                && channel.rx_count == 1
        }));
        assert!(control.channels.iter().any(|channel| {
            channel.name == "virtio-console"
                && channel.state == "ready"
                && channel.tx_count == 1
                && channel.rx_count == 1
        }));
    }

    #[test]
    fn guest_control_snapshot_rebuilds_channel_summary_from_runtime_state() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        instance
            .run_guest_command("serial::uname -a")
            .unwrap_or_else(|error| panic!("{error}"));
        instance
            .run_guest_command("guest-agent::systemctl is-system-running")
            .unwrap_or_else(|error| panic!("{error}"));

        let mut control = instance
            .guest_control
            .take()
            .unwrap_or_else(|| panic!("expected guest control state"));
        for channel in &mut control.channels {
            channel.state = String::from("unavailable");
            channel.tx_count = 99;
            channel.rx_count = 77;
            channel.last_command = Some(String::from("stale-command"));
            channel.last_exit_code = Some(55);
        }
        instance.guest_control = Some(control);

        let snapshot = instance
            .guest_control()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(snapshot.channels.iter().any(|channel| {
            channel.name == "serial"
                && channel.state == "ready"
                && channel.tx_count == 1
                && channel.rx_count == 1
                && channel.last_command.as_deref() == Some("uname -a")
                && channel.last_exit_code == Some(0)
        }));
        assert!(snapshot.channels.iter().any(|channel| {
            channel.name == "guest-agent"
                && channel.state == "ready"
                && channel.tx_count == 1
                && channel.rx_count == 1
                && channel.last_command.as_deref() == Some("systemctl is-system-running")
                && channel.last_exit_code == Some(0)
        }));
        assert!(snapshot.channels.iter().any(|channel| {
            channel.name == "virtio-console"
                && channel.state == "ready"
                && channel.tx_count == 0
                && channel.rx_count == 0
                && channel.last_command.is_none()
                && channel.last_exit_code.is_none()
        }));
    }

    #[test]
    fn repeated_guest_commands_reuse_cached_resident_programs() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let first = instance
            .run_guest_command("uname -a")
            .unwrap_or_else(|error| panic!("{error}"));
        let resident_programs_after_first = instance.execution.resident_programs.len();
        let allocations_after_first = instance.execution.guest_ram_allocations.len();
        let decoded_block_cache_after_first = instance.execution.decoded_block_cache.len();
        let decoded_block_hits_after_first = instance.execution.dbt_stats.decoded_block_cache_hits;
        let trace_chain_hits_after_first = instance.execution.dbt_stats.trace_chain_hits;

        let second = instance
            .run_guest_command("uname -a")
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(first.stdout, second.stdout);
        assert_eq!(
            instance.execution.resident_programs.len(),
            resident_programs_after_first
        );
        assert_eq!(
            instance.execution.guest_ram_allocations.len(),
            allocations_after_first
        );
        assert_eq!(
            instance.execution.decoded_block_cache.len(),
            decoded_block_cache_after_first
        );
        assert_eq!(instance.guest_command_programs.len(), 1);
        assert!(
            instance.execution.dbt_stats.decoded_block_cache_hits > decoded_block_hits_after_first
        );
        assert!(instance.execution.dbt_stats.trace_chain_hits > trace_chain_hits_after_first);
        assert!(
            instance
                .execution
                .completed_events
                .iter()
                .any(|event| event.kind == "guest_command_cache_hit")
        );
    }

    #[test]
    fn decoded_block_cache_invalidates_when_program_pages_change_generation() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let mut initial_bytecode = Vec::new();
        emit_mov_imm64(&mut initial_bytecode, ISA_REGISTER_ARG0, 1);
        emit_halt(&mut initial_bytecode);
        let program = instance
            .execution
            .register_resident_program("dbt_invalidation_probe", "guest_ram", initial_bytecode)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut control = instance
            .guest_control
            .take()
            .unwrap_or_else(|| panic!("expected guest control state"));
        instance
            .execution
            .execute_guest_program(
                &program,
                &instance.spec.machine.guest_architecture,
                instance.spec.machine.vcpu,
                instance.memory.guest_memory_bytes,
                &mut control,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let invalidations_before = instance.execution.dbt_stats.decoded_block_invalidations;
        let cache_misses_before = instance.execution.dbt_stats.decoded_block_cache_misses;
        let generation_before = instance
            .execution
            .guest_memory_bytes
            .page(program.entry_point)
            .map(|page| page.generation)
            .unwrap_or_default();

        let mut updated_bytecode = Vec::new();
        emit_mov_imm64(&mut updated_bytecode, ISA_REGISTER_ARG0, 2);
        emit_halt(&mut updated_bytecode);
        let program_index = instance
            .execution
            .resident_programs
            .iter()
            .position(|resident| resident.name == "dbt_invalidation_probe")
            .unwrap_or_else(|| panic!("expected dbt_invalidation_probe resident program"));
        let updated_program = SoftVmResidentProgram::new(
            "dbt_invalidation_probe",
            "guest_ram",
            program.entry_point,
            updated_bytecode,
        );
        instance.execution.resident_programs[program_index] = updated_program.clone();
        instance
            .execution
            .stage_resident_program(&updated_program)
            .unwrap_or_else(|error| panic!("{error}"));
        instance.execution.index_resident_program(program_index);
        let generation_after = instance
            .execution
            .guest_memory_bytes
            .page(updated_program.entry_point)
            .map(|page| page.generation)
            .unwrap_or_default();

        instance
            .execution
            .execute_guest_program(
                &updated_program,
                &instance.spec.machine.guest_architecture,
                instance.spec.machine.vcpu,
                instance.memory.guest_memory_bytes,
                &mut control,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        instance.guest_control = Some(control);

        assert!(generation_after > generation_before);
        assert!(instance.execution.dbt_stats.decoded_block_invalidations > invalidations_before);
        assert!(instance.execution.dbt_stats.decoded_block_cache_misses > cache_misses_before);
        assert_eq!(instance.execution.cpu_state.general_purpose_registers[0], 2);
    }

    #[test]
    fn fast_fault_lookup_rejects_non_executable_mapped_branch_targets() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let target = instance
            .execution
            .allocate_guest_data(
                String::from("data:non_executable_target"),
                &[ISA_OPCODE_HALT],
            )
            .unwrap_or_else(|error| panic!("{error}"));
        let mut bytecode = Vec::new();
        emit_call_abs64(&mut bytecode, target.guest_address);
        emit_halt(&mut bytecode);
        let program = instance
            .execution
            .register_resident_program("dbt_fault_lookup_probe", "guest_ram", bytecode)
            .unwrap_or_else(|error| panic!("{error}"));
        let fast_faults_before = instance.execution.dbt_stats.fast_fault_lookups;
        let mut control = instance
            .guest_control
            .take()
            .unwrap_or_else(|| panic!("expected guest control state"));
        let error = instance
            .execution
            .execute_guest_program(
                &program,
                &instance.spec.machine.guest_architecture,
                instance.spec.machine.vcpu,
                instance.memory.guest_memory_bytes,
                &mut control,
            )
            .err()
            .unwrap_or_else(|| panic!("expected non-executable branch target fault"));
        instance.guest_control = Some(control);

        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
        assert!(instance.execution.cpu_state.faulted);
        assert_eq!(instance.execution.cpu_state.fault_vector, Some(0x0e));
        assert!(
            instance
                .execution
                .cpu_state
                .fault_detail
                .as_deref()
                .is_some_and(|detail| detail.contains("violates execute permission"))
        );
        assert!(instance.execution.dbt_stats.fast_fault_lookups > fast_faults_before);
    }

    #[test]
    fn unixbench_metric_projection_redacts_host_source_path() {
        let metrics = NativeUnixBenchMetrics {
            dhrystone: 1.0,
            whetstone: 1.0,
            execl: 1.0,
            copy: 1.0,
            index: 1.0,
            source_kind: UnixBenchMetricSourceKind::HostCalibratedFull,
            source_path: Some(PathBuf::from("/tmp/secret/host-unixbench-result")),
        };
        let projections = unixbench_metric_projections(&metrics);
        let source_path = projections
            .iter()
            .find(|projection| projection.path == "/var/lib/unixbench/metrics/source_path")
            .unwrap_or_else(|| panic!("missing source_path projection"));
        assert_eq!(source_path.contents, "host-unixbench-result\n");
    }

    #[test]
    fn extract_unixbench_index_score_accepts_partial_result_lines() {
        let text = "System Benchmarks Index Score (Partial Only)                         4673.2\n";
        assert_eq!(extract_unixbench_index_score(text), Some(4673.2));
    }

    #[test]
    fn scaling_unixbench_metrics_preserves_target_index() {
        let metrics = synthetic_unixbench_metrics(2, 4 * 1024 * 1024 * 1024);
        let scaled = scale_unixbench_metrics_to_index(metrics, 4673.2);
        assert_eq!(scaled.index, 4673.2);
        assert!(scaled.copy > 0.0);
        assert!(scaled.dhrystone > 0.0);
        assert!(scaled.whetstone > 0.0);
        assert!(scaled.execl > 0.0);
    }

    #[test]
    fn scaling_unixbench_metrics_marks_host_calibrated_partial_provenance() {
        let metrics = synthetic_unixbench_metrics(2, 4 * 1024 * 1024 * 1024);
        let host_score = HostUnixBenchScore {
            index: 4673.2,
            source_path: PathBuf::from("/tmp/unixbench-partial"),
            partial: true,
        };
        let scaled = scale_unixbench_metrics_to_host_score(metrics, &host_score);
        assert_eq!(scaled.index, 4673.2);
        assert_eq!(
            scaled.source_kind,
            UnixBenchMetricSourceKind::HostCalibratedPartial
        );
        assert_eq!(
            scaled.source_path.as_deref(),
            Some(Path::new("/tmp/unixbench-partial"))
        );
    }

    #[test]
    fn latest_host_unixbench_score_ignores_newer_unscored_results() {
        let temp_root = std::env::temp_dir().join(format!(
            "uhost-softvm-host-unixbench-results-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&temp_root).unwrap_or_else(|error| panic!("{error}"));
        let scored = temp_root.join("older");
        let unscored = temp_root.join("newer");
        std::fs::write(
            &scored,
            "System Benchmarks Index Score (Partial Only)                         4673.2\n",
        )
        .unwrap_or_else(|error| panic!("{error}"));
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&unscored, "still running\n").unwrap_or_else(|error| panic!("{error}"));

        let score = latest_host_unixbench_score_in_dir(&temp_root)
            .unwrap_or_else(|| panic!("expected scored UnixBench result"));
        assert_eq!(score.index, 4673.2);
        assert_eq!(score.source_path, scored);
        assert!(score.partial);
    }

    #[test]
    fn native_execution_core_models_local_disks_and_install_media_as_block_devices() {
        let temp_root =
            std::env::temp_dir().join(format!("uhost-softvm-artifacts-{}", std::process::id()));
        std::fs::create_dir_all(&temp_root).unwrap_or_else(|error| panic!("{error}"));
        let disk_path = temp_root.join("disk.raw");
        let iso_path = temp_root.join("installer.iso");
        std::fs::write(&disk_path, b"disk-bytes").unwrap_or_else(|error| panic!("{error}"));
        std::fs::write(&iso_path, b"iso-bytes").unwrap_or_else(|error| panic!("{error}"));

        let machine = MachineSpec::new(
            MachineFamily::GeneralPurposePci,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioBalanced,
            BootPath::GeneralPurpose,
            "bios",
            disk_path.to_string_lossy().into_owned(),
            Some(iso_path.to_string_lossy().into_owned()),
            BootDevice::Cdrom,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine);
        let instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(instance.execution.memory_regions.len(), 2);
        assert!(
            instance
                .execution
                .guest_ram_allocations
                .iter()
                .any(|allocation| allocation.label == "program:boot_dispatch")
        );
        assert!(
            instance
                .execution
                .boot_artifacts
                .iter()
                .any(|artifact| artifact.role == "install_media"
                    && artifact.delivery_model == "block_device"
                    && artifact.preview_loaded_bytes == 0
                    && artifact.read_only
                    && artifact.overlay.is_none())
        );
    }

    #[test]
    fn local_files_only_policy_rejects_catalog_style_artifacts() {
        let catalog_machine = MachineSpec::new(
            MachineFamily::GeneralPurposePci,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioBalanced,
            BootPath::GeneralPurpose,
            "uefi_standard",
            "object://images/linux.raw",
            None,
            BootDevice::Disk,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, catalog_machine);
        let error =
            SoftVmInstance::new_with_artifact_policy(spec, SoftVmArtifactPolicy::LocalFilesOnly)
                .expect_err("catalog-style artifacts must be rejected in local-files-only mode");
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert!(error.message.contains(
            "software-backed VM execution requires a local absolute path or file:// URI"
        ));
    }

    #[test]
    fn start_rejects_catalog_style_artifacts_under_execution_mode() {
        let catalog_machine = MachineSpec::new(
            MachineFamily::GeneralPurposePci,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioBalanced,
            BootPath::GeneralPurpose,
            "uefi_standard",
            "object://images/linux.raw",
            None,
            BootDevice::Disk,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, catalog_machine);
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        let error = instance
            .start()
            .expect_err("execution mode must reject non-local boot artifacts");
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert!(error.message.contains(
            "software-backed VM execution requires a local absolute path or file:// URI"
        ));
    }

    #[test]
    fn local_files_only_policy_accepts_file_uri_artifacts() {
        let temp_root = std::env::temp_dir().join(format!(
            "uhost-softvm-file-uri-artifacts-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&temp_root).unwrap_or_else(|error| panic!("{error}"));
        let disk_path = temp_root.join("disk.raw");
        std::fs::write(&disk_path, b"disk-bytes").unwrap_or_else(|error| panic!("{error}"));

        let machine = MachineSpec::new(
            MachineFamily::GeneralPurposePci,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioBalanced,
            BootPath::GeneralPurpose,
            "bios",
            format!("file://{}", disk_path.display()),
            None,
            BootDevice::Disk,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine);
        let instance =
            SoftVmInstance::new_with_artifact_policy(spec, SoftVmArtifactPolicy::LocalFilesOnly)
                .unwrap_or_else(|error| panic!("{error}"));

        assert!(
            instance
                .execution
                .boot_artifacts
                .iter()
                .any(|artifact| artifact.role == "primary_disk"
                    && artifact.delivery_model == "block_device"
                    && artifact.preview_loaded_bytes == 0
                    && !artifact.read_only
                    && artifact.overlay.is_some())
        );
    }

    #[test]
    fn local_files_only_policy_accepts_builtin_firmware_with_local_disk() {
        let temp_root = std::env::temp_dir().join(format!(
            "uhost-softvm-builtin-firmware-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&temp_root).unwrap_or_else(|error| panic!("{error}"));
        let disk_path = temp_root.join("disk.raw");
        std::fs::write(&disk_path, b"disk-bytes").unwrap_or_else(|error| panic!("{error}"));

        let machine = MachineSpec::new(
            MachineFamily::GeneralPurposePci,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioBalanced,
            BootPath::GeneralPurpose,
            "uefi_standard",
            disk_path.to_string_lossy().into_owned(),
            None,
            BootDevice::Disk,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine);
        let instance =
            SoftVmInstance::new_with_artifact_policy(spec, SoftVmArtifactPolicy::LocalFilesOnly)
                .unwrap_or_else(|error| panic!("{error}"));

        assert!(
            instance
                .execution
                .boot_artifacts
                .iter()
                .any(|artifact| artifact.role == "firmware" && artifact.source == "uefi_standard")
        );
        assert!(
            instance
                .execution
                .boot_artifacts
                .iter()
                .any(|artifact| artifact.role == "primary_disk"
                    && artifact.delivery_model == "block_device"
                    && artifact.preview_loaded_bytes == 0
                    && !artifact.read_only
                    && artifact.overlay.is_some())
        );
    }

    #[test]
    fn block_backed_primary_disk_supports_thin_overlay_reads_and_writes() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance =
            SoftVmInstance::new_with_artifact_policy(spec, SoftVmArtifactPolicy::LocalFilesOnly)
                .unwrap_or_else(|error| panic!("{error}"));

        let original = instance
            .execution
            .read_boot_artifact_range("primary_disk", 0, 8)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(original, b"softvm-t");

        instance
            .execution
            .write_boot_artifact_overlay("primary_disk", 0, b"OVLY")
            .unwrap_or_else(|error| panic!("{error}"));

        let mutated = instance
            .execution
            .read_boot_artifact_range("primary_disk", 0, 8)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(mutated, b"OVLYvm-t");
        let persisted =
            std::fs::read(staged_disk_artifact_source()).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(&persisted[..8], b"softvm-t");

        let disk_artifact = instance
            .execution
            .boot_artifacts
            .iter()
            .find(|artifact| artifact.role == "primary_disk")
            .unwrap_or_else(|| panic!("missing primary_disk artifact"));
        let overlay = disk_artifact
            .overlay
            .as_ref()
            .unwrap_or_else(|| panic!("missing writable overlay"));
        assert_eq!(overlay.modified_blocks.len(), 1);
        assert_eq!(overlay.allocated_bytes, u64::from(DEFAULT_BLOCK_SIZE_BYTES));
    }

    #[test]
    fn install_media_overlay_writes_are_rejected() {
        let machine = MachineSpec::new(
            MachineFamily::GeneralPurposePci,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioBalanced,
            BootPath::GeneralPurpose,
            "bios",
            staged_disk_artifact_source(),
            Some(staged_install_artifact_source()),
            BootDevice::Cdrom,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine);
        let mut instance =
            SoftVmInstance::new_with_artifact_policy(spec, SoftVmArtifactPolicy::LocalFilesOnly)
                .unwrap_or_else(|error| panic!("{error}"));

        let error = instance
            .execution
            .write_boot_artifact_overlay("install_media", 0, b"x")
            .expect_err("expected read-only install media rejection");
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert!(error.message.contains("read-only"));
    }

    #[test]
    fn local_files_only_policy_rejects_relative_file_uri_artifacts() {
        let machine = MachineSpec::new(
            MachineFamily::GeneralPurposePci,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioBalanced,
            BootPath::GeneralPurpose,
            "bios",
            String::from("file://relative-disk.raw"),
            None,
            BootDevice::Disk,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine);
        let error =
            SoftVmInstance::new_with_artifact_policy(spec, SoftVmArtifactPolicy::LocalFilesOnly)
                .expect_err("relative file URIs must be rejected in local-files-only mode");

        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert!(error.message.contains(
            "software-backed VM execution requires a local absolute path or file:// URI"
        ));
    }

    #[test]
    fn invalid_guest_opcode_records_fault_state() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.start().unwrap_or_else(|error| panic!("{error}"));

        let mut control = instance
            .guest_control
            .take()
            .unwrap_or_else(|| panic!("expected guest control state"));
        let program = instance
            .execution
            .register_resident_program("guest_fault_probe", "guest_ram", vec![0x7f])
            .unwrap_or_else(|error| panic!("{error}"));

        let error = instance
            .execution
            .execute_guest_program(
                &program,
                &instance.spec.machine.guest_architecture,
                instance.spec.machine.vcpu,
                instance.memory.guest_memory_bytes,
                &mut control,
            )
            .err()
            .unwrap_or_else(|| panic!("expected invalid guest opcode failure"));

        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
        assert!(instance.execution.cpu_state.faulted);
        assert_eq!(instance.execution.cpu_state.fault_vector, Some(0x06));
        assert!(
            instance
                .execution
                .cpu_state
                .fault_detail
                .as_deref()
                .is_some_and(|detail| detail.contains("unsupported guest-isa opcode"))
        );
        assert_eq!(instance.execution.cpu_state.trap_frame_depth, 1);
        assert!(
            instance
                .execution
                .pending_interrupts
                .iter()
                .any(|interrupt| interrupt.source == "cpu_fault" && interrupt.vector == 0x06)
        );
    }

    #[test]
    fn duplicate_prepare_is_rejected() {
        let spec = SoftVmRuntimeSpec::new(ExecutionClass::Balanced, machine());
        let mut instance = SoftVmInstance::new(spec).unwrap_or_else(|error| panic!("{error}"));
        instance.prepare().unwrap_or_else(|error| panic!("{error}"));
        let error = instance
            .prepare()
            .err()
            .unwrap_or_else(|| panic!("expected prepare conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }
}
