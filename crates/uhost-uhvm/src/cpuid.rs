use kvm_bindings::{CpuId, kvm_cpuid_entry2};
use kvm_ioctls::{Cap, Kvm, VcpuFd};

use crate::{Result, UhvmError};

/// Applies a KVM-supported CPUID profile with consistent guest topology.
pub fn configure_cpuid(kvm: &Kvm, vcpu: &VcpuFd, cpu_id: u8, vcpus: u8) -> Result<()> {
    let mut cpuid = kvm
        .get_supported_cpuid(256)
        .map_err(|error| UhvmError::new(format!("read supported CPUID: {error}")))?;
    let tsc_deadline_supported = kvm.check_extension(Cap::TscDeadlineTimer);
    let topology_shift = u32::from(vcpus.saturating_sub(1))
        .next_power_of_two()
        .trailing_zeros();
    for entry in cpuid.as_mut_slice() {
        match entry.function {
            1 => {
                entry.ebx = (entry.ebx & 0x0000_ffff)
                    | (u32::from(vcpus) << 16)
                    | (u32::from(cpu_id) << 24);
                entry.ecx = (entry.ecx & !(1 << 24))
                    | (u32::from(tsc_deadline_supported) << 24)
                    | (1 << 31);
            }
            4 => {
                let cache_level = (entry.eax >> 5) & 0x07;
                let shared_logical_processors = if cache_level >= 3 {
                    u32::from(vcpus - 1)
                } else {
                    0
                };
                entry.eax = (entry.eax & !((0x3f << 26) | (0x0fff << 14)))
                    | (shared_logical_processors << 26)
                    | (u32::from(vcpus - 1) << 14);
            }
            0x0b | 0x1f => {
                entry.edx = u32::from(cpu_id);
                if entry.index == 0 {
                    entry.eax = 0;
                    entry.ebx = 1;
                    entry.ecx = (entry.index & 0xff) | (1 << 8);
                } else if entry.index == 1 {
                    entry.eax = topology_shift;
                    entry.ebx = u32::from(vcpus);
                    entry.ecx = (entry.index & 0xff) | (2 << 8);
                } else {
                    entry.eax = 0;
                    entry.ebx = 0;
                    entry.ecx = entry.index & 0xff;
                }
            }
            _ => {}
        }
    }
    if !cpuid
        .as_slice()
        .iter()
        .any(|entry| entry.function == 0x4000_0000)
    {
        let mut entries = cpuid.as_slice().to_vec();
        entries.push(kvm_cpuid_entry2 {
            function: 0x4000_0000,
            eax: 0x4000_0001,
            ebx: u32::from_le_bytes(*b"KVMK"),
            ecx: u32::from_le_bytes(*b"VMKV"),
            edx: u32::from_le_bytes(*b"M\0\0\0"),
            ..kvm_cpuid_entry2::default()
        });
        entries.push(kvm_cpuid_entry2 {
            function: 0x4000_0001,
            eax: 0x1,
            ..kvm_cpuid_entry2::default()
        });
        cpuid = CpuId::from_entries(&entries)
            .map_err(|error| UhvmError::new(format!("build guest CPUID: {error}")))?;
    }
    vcpu.set_cpuid2(&cpuid)
        .map_err(|error| UhvmError::new(format!("set guest CPUID: {error}")))?;
    Ok(())
}
