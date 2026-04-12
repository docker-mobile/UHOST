//! Minimal machine-model primitives for software-backed UVM execution.

use serde::{Deserialize, Serialize};
use uhost_core::{PlatformError, Result};
use uhost_uvm::{BootDevice, BootPath, DeviceModel, GuestArchitecture, MachineFamily};

/// Boot medium selected for the machine contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootMedium {
    /// Optional direct-kernel boot reserved for microvm compatibility paths.
    DirectKernel,
    /// Firmware-mediated boot for the default full-VM path.
    Firmware,
}

impl BootMedium {
    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectKernel => "direct_kernel",
            Self::Firmware => "firmware",
        }
    }
}

/// Minimal boot contract passed into a software-backed machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootContract {
    /// Boot medium.
    pub medium: String,
    /// Firmware profile or direct-kernel policy key.
    pub firmware_profile: String,
    /// Initial boot device.
    pub primary_boot_device: String,
    /// Disk or object reference used for boot.
    pub disk_image: String,
    /// Optional ISO or CD-ROM install media.
    pub cdrom_image: Option<String>,
}

impl BootContract {
    /// Construct a boot contract from the phase-0 UVM launch shape.
    pub fn from_launch(
        machine_family: MachineFamily,
        boot_path: BootPath,
        firmware_profile: impl Into<String>,
        disk_image: impl Into<String>,
        cdrom_image: Option<String>,
        boot_device: BootDevice,
    ) -> Result<Self> {
        let firmware_profile = firmware_profile.into();
        if firmware_profile.trim().is_empty() {
            return Err(PlatformError::invalid("firmware_profile may not be empty"));
        }
        let disk_image = disk_image.into();
        if disk_image.trim().is_empty() {
            return Err(PlatformError::invalid("disk_image may not be empty"));
        }
        let medium = match (machine_family, boot_path) {
            (MachineFamily::MicrovmLinux, BootPath::MicroVm) => BootMedium::DirectKernel,
            _ => BootMedium::Firmware,
        };
        let cdrom_image = cdrom_image
            .map(|value| {
                let trimmed = value.trim().to_owned();
                if trimmed.is_empty() {
                    return Err(PlatformError::invalid("cdrom_image may not be empty"));
                }
                Ok(trimmed)
            })
            .transpose()?;
        if boot_device == BootDevice::Cdrom && cdrom_image.is_none() {
            return Err(PlatformError::conflict(
                "cdrom boot requires attached install media",
            ));
        }
        if medium == BootMedium::DirectKernel
            && (boot_device != BootDevice::Disk || cdrom_image.is_some())
        {
            return Err(PlatformError::conflict(
                "direct-kernel microvm boot path does not support cdrom install media",
            ));
        }
        Ok(Self {
            medium: String::from(medium.as_str()),
            firmware_profile,
            primary_boot_device: String::from(boot_device.as_str()),
            disk_image,
            cdrom_image,
        })
    }
}

/// Named memory region exported by a machine-family topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineMemoryRegion {
    /// Stable region name.
    pub name: String,
    /// Stable region kind used by runtime helpers.
    pub kind: String,
    /// Guest physical base address.
    pub guest_physical_base: u64,
    /// Region byte length.
    pub byte_len: u64,
    /// Whether the region is writable.
    pub writable: bool,
}

/// MMIO-backed device exported by a machine-family topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineDevice {
    /// Stable device name.
    pub name: String,
    /// Stable device kind used by runtime helpers.
    pub kind: String,
    /// Guest physical base address for the MMIO window.
    pub guest_physical_base: u64,
    /// MMIO window byte length.
    pub byte_len: u64,
    /// Read-dispatch route exposed by the device.
    pub read_dispatch: String,
    /// Write-dispatch route exposed by the device.
    pub write_dispatch: String,
    /// Optional interrupt source raised by the device.
    pub irq_source: Option<String>,
}

/// Interrupt route exported by a machine-family topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineInterrupt {
    /// Stable interrupt source name.
    pub source: String,
    /// Interrupt vector raised for the source.
    pub vector: u8,
    /// Trigger semantics for the interrupt route.
    pub trigger: String,
}

/// Timer source exported by a machine-family topology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineTimer {
    /// Stable timer name.
    pub name: String,
    /// Stable interrupt source raised by the timer.
    pub source: String,
    /// MMIO device name hosting the timer control surface.
    pub mmio_device: String,
    /// Synthetic timer frequency used by the software substrate.
    pub tick_hz: u64,
    /// Interrupt vector associated with the timer source.
    pub interrupt_vector: u8,
}

/// Per-family machine topology derived from a stable machine contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineTopology {
    /// Reset vector used by the guest execution core.
    pub reset_vector: u64,
    /// Memory map reserved by the machine family.
    pub memory_regions: Vec<MachineMemoryRegion>,
    /// MMIO-backed devices exposed by the machine family.
    pub devices: Vec<MachineDevice>,
    /// Interrupt routes exposed by the machine family.
    pub interrupts: Vec<MachineInterrupt>,
    /// Timer sources exposed by the machine family.
    pub timers: Vec<MachineTimer>,
}

impl MachineTopology {
    /// Look up a memory region by stable name.
    pub fn memory_region_named(&self, name: &str) -> Option<&MachineMemoryRegion> {
        self.memory_regions
            .iter()
            .find(|region| region.name == name)
    }

    /// Look up a memory region by stable kind.
    pub fn memory_region_by_kind(&self, kind: &str) -> Option<&MachineMemoryRegion> {
        self.memory_regions
            .iter()
            .find(|region| region.kind == kind)
    }

    /// Look up a device by stable name.
    pub fn device_named(&self, name: &str) -> Option<&MachineDevice> {
        self.devices.iter().find(|device| device.name == name)
    }

    /// Look up a device by stable kind.
    pub fn device_by_kind(&self, kind: &str) -> Option<&MachineDevice> {
        self.devices.iter().find(|device| device.kind == kind)
    }

    /// Look up an interrupt route by source.
    pub fn interrupt_for_source(&self, source: &str) -> Option<&MachineInterrupt> {
        self.interrupts
            .iter()
            .find(|interrupt| interrupt.source == source)
    }

    /// Look up a timer by source.
    pub fn timer_for_source(&self, source: &str) -> Option<&MachineTimer> {
        self.timers.iter().find(|timer| timer.source == source)
    }
}

/// Minimal memory-layout view synthesized for a software-backed guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryLayout {
    /// Total guest memory in bytes.
    pub guest_memory_bytes: u64,
    /// Number of coarse memory slots used by the runner skeleton.
    pub slot_count: u16,
    /// Per-family topology derived from the machine contract.
    pub topology: MachineTopology,
}

/// Minimal machine description used by the software backend skeleton.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineSpec {
    /// Machine family.
    pub machine_family: String,
    /// Guest architecture.
    pub guest_architecture: String,
    /// Virtual CPU count.
    pub vcpu: u16,
    /// Guest memory in MiB.
    pub memory_mb: u64,
    /// Device model.
    pub device_model: String,
    /// Boot-path contract.
    pub boot_path: String,
    /// Boot contract.
    pub boot: BootContract,
}

impl MachineSpec {
    /// Construct and validate a minimal software-backed machine description.
    pub fn new(
        machine_family: MachineFamily,
        guest_architecture: GuestArchitecture,
        vcpu: u16,
        memory_mb: u64,
        device_model: DeviceModel,
        boot_path: BootPath,
        firmware_profile: impl Into<String>,
        disk_image: impl Into<String>,
        cdrom_image: Option<String>,
        boot_device: BootDevice,
    ) -> Result<Self> {
        if vcpu == 0 {
            return Err(PlatformError::invalid("vcpu must be at least 1"));
        }
        if memory_mb < 256 {
            return Err(PlatformError::invalid("memory_mb must be at least 256 MiB"));
        }
        if machine_family == MachineFamily::Aarch64Virt
            && guest_architecture != GuestArchitecture::Aarch64
        {
            return Err(PlatformError::conflict(
                "aarch64_virt machine family requires aarch64 guest architecture",
            ));
        }
        if machine_family == MachineFamily::MicrovmLinux
            && guest_architecture != GuestArchitecture::X86_64
        {
            return Err(PlatformError::conflict(
                "microvm_linux machine family currently requires x86_64 guest architecture",
            ));
        }
        if boot_path == BootPath::AppleVm && machine_family != MachineFamily::Aarch64Virt {
            return Err(PlatformError::conflict(
                "apple_vm boot path requires aarch64_virt machine family",
            ));
        }
        if device_model == DeviceModel::AppleIntegrated
            && machine_family != MachineFamily::Aarch64Virt
        {
            return Err(PlatformError::conflict(
                "apple_integrated device model requires aarch64_virt machine family",
            ));
        }
        let boot = BootContract::from_launch(
            machine_family,
            boot_path,
            firmware_profile,
            disk_image,
            cdrom_image,
            boot_device,
        )?;
        Ok(Self {
            machine_family: String::from(machine_family.as_str()),
            guest_architecture: String::from(guest_architecture.as_str()),
            vcpu,
            memory_mb,
            device_model: String::from(device_model.as_str()),
            boot_path: String::from(boot_path.as_str()),
            boot,
        })
    }

    /// Build the machine-family topology used by the software substrate.
    pub fn topology(&self) -> Result<MachineTopology> {
        let guest_memory_bytes = self
            .memory_mb
            .checked_mul(1024)
            .and_then(|value| value.checked_mul(1024))
            .ok_or_else(|| PlatformError::invalid("memory_mb is too large for byte conversion"))?;
        match self.machine_family.as_str() {
            "microvm_linux" => Ok(build_microvm_linux_topology(guest_memory_bytes)),
            "general_purpose_pci" => Ok(build_general_purpose_pci_topology(
                &self.boot.firmware_profile,
                guest_memory_bytes,
            )),
            "aarch64_virt" => Ok(build_aarch64_virt_topology(guest_memory_bytes)),
            _ => Err(PlatformError::invalid(format!(
                "unsupported machine family `{}` for topology synthesis",
                self.machine_family
            ))),
        }
    }

    /// Synthesize a minimal guest memory layout for the runner skeleton.
    pub fn memory_layout(&self) -> Result<MemoryLayout> {
        let topology = self.topology()?;
        let guest_memory_bytes = topology
            .memory_region_by_kind("guest_ram")
            .map(|region| region.byte_len)
            .ok_or_else(|| PlatformError::invalid("machine topology is missing guest RAM"))?;
        let slot_count = if self.machine_family == MachineFamily::MicrovmLinux.as_str() {
            1
        } else {
            2
        };
        Ok(MemoryLayout {
            guest_memory_bytes,
            slot_count,
            topology,
        })
    }
}

fn build_microvm_linux_topology(guest_memory_bytes: u64) -> MachineTopology {
    let interrupt_vector = 0x20;
    MachineTopology {
        reset_vector: 0x0002_0000,
        memory_regions: vec![
            memory_region("guest_ram", "guest_ram", 0, guest_memory_bytes, true),
            memory_region(
                "direct_kernel_image",
                "firmware",
                0x0002_0000,
                0x0002_0000,
                false,
            ),
            memory_region(
                "primary_disk_window",
                "primary_disk",
                0x0040_0000,
                0x0040_0000,
                false,
            ),
            memory_region(
                "install_media_window",
                "install_media",
                0x0080_0000,
                0x0080_0000,
                false,
            ),
        ],
        devices: vec![
            mmio_device(
                "uart_console",
                "console",
                0x1000_0000,
                "console_rx",
                "console_tx",
                Some("uart_console"),
            ),
            mmio_device(
                "virt_timer",
                "timer",
                0x1000_1000,
                "timer_state",
                "timer_control",
                Some("virt_timer"),
            ),
            mmio_device(
                "virt_block_control",
                "block_control",
                0x1000_2000,
                "block_status",
                "block_queue",
                Some("virt_block_control"),
            ),
            mmio_device(
                "virtio_console",
                "virtio_console",
                0x1000_3000,
                "console_queue_rx",
                "console_queue_tx",
                Some("virtio_console"),
            ),
            mmio_device(
                "virtio_rng",
                "virtio_rng",
                0x1000_4000,
                "entropy_queue",
                "rng_control",
                Some("virtio_rng"),
            ),
            mmio_device(
                "virtio_net",
                "virtio_net",
                0x1000_5000,
                "net_queue_rx",
                "net_queue_tx",
                Some("virtio_net"),
            ),
        ],
        interrupts: vec![
            interrupt_route("virt_timer", interrupt_vector, "edge_rising"),
            interrupt_route("virtio_rng", 0x21, "level_high"),
            interrupt_route("virt_block_control", 0x22, "level_high"),
            interrupt_route("virtio_net", 0x23, "level_high"),
            interrupt_route("uart_console", 0x24, "level_high"),
            interrupt_route("virtio_console", 0x25, "level_high"),
        ],
        timers: vec![timer_source(
            "lapic_timer",
            "virt_timer",
            "virt_timer",
            250,
            interrupt_vector,
        )],
    }
}

fn build_general_purpose_pci_topology(
    firmware_profile: &str,
    guest_memory_bytes: u64,
) -> MachineTopology {
    let interrupt_vector = 0x20;
    MachineTopology {
        reset_vector: if firmware_profile == "bios" {
            0x000f_fff0
        } else {
            0x0010_0000
        },
        memory_regions: vec![
            memory_region("guest_ram", "guest_ram", 0, guest_memory_bytes, true),
            memory_region("firmware", "firmware", 0x000f_0000, 0x0002_0000, false),
            memory_region(
                "primary_disk_window",
                "primary_disk",
                0x0010_0000,
                0x0080_0000,
                false,
            ),
            memory_region(
                "install_media_window",
                "install_media",
                0x0100_0000,
                0x0100_0000,
                false,
            ),
        ],
        devices: vec![
            mmio_device(
                "uart_console",
                "console",
                0x1000_0000,
                "console_rx",
                "console_tx",
                Some("uart_console"),
            ),
            mmio_device(
                "virt_timer",
                "timer",
                0x1001_0000,
                "timer_state",
                "timer_control",
                Some("virt_timer"),
            ),
            mmio_device(
                "virt_block_control",
                "block_control",
                0x1002_0000,
                "block_status",
                "block_queue",
                Some("virt_block_control"),
            ),
            mmio_device(
                "virtio_console",
                "virtio_console",
                0x1003_0000,
                "console_queue_rx",
                "console_queue_tx",
                Some("virtio_console"),
            ),
            mmio_device(
                "virtio_rng",
                "virtio_rng",
                0x1004_0000,
                "entropy_queue",
                "rng_control",
                Some("virtio_rng"),
            ),
            mmio_device(
                "virtio_net",
                "virtio_net",
                0x1005_0000,
                "net_queue_rx",
                "net_queue_tx",
                Some("virtio_net"),
            ),
        ],
        interrupts: vec![
            interrupt_route("virt_timer", interrupt_vector, "edge_rising"),
            interrupt_route("virtio_rng", 0x21, "level_high"),
            interrupt_route("virt_block_control", 0x22, "level_high"),
            interrupt_route("virtio_net", 0x23, "level_high"),
            interrupt_route("uart_console", 0x24, "level_high"),
            interrupt_route("virtio_console", 0x25, "level_high"),
        ],
        timers: vec![timer_source(
            "pit_tick",
            "virt_timer",
            "virt_timer",
            100,
            interrupt_vector,
        )],
    }
}

fn build_aarch64_virt_topology(guest_memory_bytes: u64) -> MachineTopology {
    let interrupt_vector = 0x30;
    MachineTopology {
        reset_vector: 0x0008_0000,
        memory_regions: vec![
            memory_region("guest_ram", "guest_ram", 0, guest_memory_bytes, true),
            memory_region("firmware", "firmware", 0x0008_0000, 0x0008_0000, false),
            memory_region(
                "primary_disk_window",
                "primary_disk",
                0x0800_0000,
                0x0080_0000,
                false,
            ),
            memory_region(
                "install_media_window",
                "install_media",
                0x0900_0000,
                0x0100_0000,
                false,
            ),
        ],
        devices: vec![
            mmio_device(
                "uart_console",
                "console",
                0x0a00_0000,
                "console_rx",
                "console_tx",
                Some("uart_console"),
            ),
            mmio_device(
                "virt_timer",
                "timer",
                0x0a01_0000,
                "timer_state",
                "timer_control",
                Some("virt_timer"),
            ),
            mmio_device(
                "virt_block_control",
                "block_control",
                0x0a02_0000,
                "block_status",
                "block_queue",
                Some("virt_block_control"),
            ),
            mmio_device(
                "virtio_console",
                "virtio_console",
                0x0a03_0000,
                "console_queue_rx",
                "console_queue_tx",
                Some("virtio_console"),
            ),
            mmio_device(
                "virtio_rng",
                "virtio_rng",
                0x0a04_0000,
                "entropy_queue",
                "rng_control",
                Some("virtio_rng"),
            ),
            mmio_device(
                "virtio_net",
                "virtio_net",
                0x0a05_0000,
                "net_queue_rx",
                "net_queue_tx",
                Some("virtio_net"),
            ),
        ],
        interrupts: vec![
            interrupt_route("virt_timer", interrupt_vector, "level_high"),
            interrupt_route("virtio_rng", 0x31, "level_high"),
            interrupt_route("virt_block_control", 0x32, "level_high"),
            interrupt_route("virtio_net", 0x33, "level_high"),
            interrupt_route("uart_console", 0x34, "level_high"),
            interrupt_route("virtio_console", 0x35, "level_high"),
        ],
        timers: vec![timer_source(
            "arch_timer",
            "virt_timer",
            "virt_timer",
            1000,
            interrupt_vector,
        )],
    }
}

fn memory_region(
    name: &str,
    kind: &str,
    guest_physical_base: u64,
    byte_len: u64,
    writable: bool,
) -> MachineMemoryRegion {
    MachineMemoryRegion {
        name: String::from(name),
        kind: String::from(kind),
        guest_physical_base,
        byte_len,
        writable,
    }
}

fn mmio_device(
    name: &str,
    kind: &str,
    guest_physical_base: u64,
    read_dispatch: &str,
    write_dispatch: &str,
    irq_source: Option<&str>,
) -> MachineDevice {
    MachineDevice {
        name: String::from(name),
        kind: String::from(kind),
        guest_physical_base,
        byte_len: 0x1000,
        read_dispatch: String::from(read_dispatch),
        write_dispatch: String::from(write_dispatch),
        irq_source: irq_source.map(String::from),
    }
}

fn interrupt_route(source: &str, vector: u8, trigger: &str) -> MachineInterrupt {
    MachineInterrupt {
        source: String::from(source),
        vector,
        trigger: String::from(trigger),
    }
}

fn timer_source(
    name: &str,
    source: &str,
    mmio_device: &str,
    tick_hz: u64,
    interrupt_vector: u8,
) -> MachineTimer {
    MachineTimer {
        name: String::from(name),
        source: String::from(source),
        mmio_device: String::from(mmio_device),
        tick_hz,
        interrupt_vector,
    }
}

#[cfg(test)]
mod tests {
    use super::{BootMedium, MachineSpec};
    use uhost_uvm::{BootDevice, BootPath, DeviceModel, GuestArchitecture, MachineFamily};

    #[test]
    fn general_purpose_linux_uses_firmware_boot_contract() {
        let machine = MachineSpec::new(
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
        assert_eq!(machine.boot.medium, BootMedium::Firmware.as_str());
        assert_eq!(
            machine
                .memory_layout()
                .unwrap_or_else(|error| panic!("{error}"))
                .slot_count,
            2
        );
        let topology = machine.topology().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(topology.reset_vector, 0x0010_0000);
        assert_eq!(
            topology
                .memory_region_by_kind("firmware")
                .unwrap_or_else(|| panic!("expected firmware region"))
                .guest_physical_base,
            0x000f_0000
        );
        assert_eq!(
            topology
                .device_by_kind("timer")
                .unwrap_or_else(|| panic!("expected timer device"))
                .guest_physical_base,
            0x1001_0000
        );
        assert_eq!(
            topology
                .interrupt_for_source("virt_timer")
                .unwrap_or_else(|| panic!("expected timer interrupt"))
                .vector,
            0x20
        );
    }

    #[test]
    fn general_purpose_linux_accepts_cdrom_install_media() {
        let machine = MachineSpec::new(
            MachineFamily::GeneralPurposePci,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioBalanced,
            BootPath::GeneralPurpose,
            "bios",
            "object://images/linux.raw",
            Some(String::from("file:///isos/ubuntu-26.04.iso")),
            BootDevice::Cdrom,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(machine.boot.primary_boot_device, "cdrom");
        assert_eq!(
            machine.boot.cdrom_image.as_deref(),
            Some("file:///isos/ubuntu-26.04.iso")
        );
    }

    #[test]
    fn microvm_linux_uses_direct_kernel_boot_contract() {
        let machine = MachineSpec::new(
            MachineFamily::MicrovmLinux,
            GuestArchitecture::X86_64,
            2,
            2048,
            DeviceModel::VirtioMinimal,
            BootPath::MicroVm,
            "uefi_standard",
            "object://images/linux.raw",
            None,
            BootDevice::Disk,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(machine.boot.medium, BootMedium::DirectKernel.as_str());
        assert_eq!(
            machine
                .memory_layout()
                .unwrap_or_else(|error| panic!("{error}"))
                .guest_memory_bytes,
            2_147_483_648
        );
        let topology = machine.topology().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(topology.reset_vector, 0x0002_0000);
        assert_eq!(
            topology
                .memory_region_by_kind("primary_disk")
                .unwrap_or_else(|| panic!("expected disk window"))
                .guest_physical_base,
            0x0040_0000
        );
        assert_eq!(
            topology
                .timer_for_source("virt_timer")
                .unwrap_or_else(|| panic!("expected timer source"))
                .name,
            "lapic_timer"
        );
    }

    #[test]
    fn aarch64_machine_rejects_x86_guest_architecture() {
        let error = MachineSpec::new(
            MachineFamily::Aarch64Virt,
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
        .err()
        .unwrap_or_else(|| panic!("expected machine-family conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[test]
    fn aarch64_topology_uses_family_specific_addresses_and_vectors() {
        let machine = MachineSpec::new(
            MachineFamily::Aarch64Virt,
            GuestArchitecture::Aarch64,
            4,
            4096,
            DeviceModel::AppleIntegrated,
            BootPath::AppleVm,
            "uefi_standard",
            "object://images/linux-aarch64.raw",
            None,
            BootDevice::Disk,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let topology = machine.topology().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(topology.reset_vector, 0x0008_0000);
        assert_eq!(
            topology
                .memory_region_by_kind("primary_disk")
                .unwrap_or_else(|| panic!("expected disk window"))
                .guest_physical_base,
            0x0800_0000
        );
        assert_eq!(
            topology
                .device_by_kind("console")
                .unwrap_or_else(|| panic!("expected console device"))
                .guest_physical_base,
            0x0a00_0000
        );
        assert_eq!(
            topology
                .interrupt_for_source("virt_timer")
                .unwrap_or_else(|| panic!("expected timer interrupt"))
                .vector,
            0x30
        );
        assert_eq!(
            topology
                .timer_for_source("virt_timer")
                .unwrap_or_else(|| panic!("expected timer source"))
                .name,
            "arch_timer"
        );
    }
}
