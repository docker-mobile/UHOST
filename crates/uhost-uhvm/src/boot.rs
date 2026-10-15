use std::fs;

use kvm_bindings::{Msrs, kvm_fpu, kvm_msr_entry, kvm_regs, kvm_segment};
use kvm_ioctls::VcpuFd;

use crate::{Result, UhvmError, sys::memory::GuestMemory};

const BOOT_PARAMS_GPA: u64 = 0x7000;
const CMDLINE_GPA: u64 = 0x20000;
const GDT_GPA: u64 = 0x500;
const PML4_GPA: u64 = 0x9000;
const PDPT_GPA: u64 = 0xa000;
const PD_GPA: u64 = 0xb000;
const E820_MAX_ENTRIES: usize = 128;
const E820_RAM: u32 = 1;
const BDA_EBDA_SEGMENT_GPA: u64 = 0x40e;
const BDA_MEMORY_KIB_GPA: u64 = 0x413;
const EBDA_GPA: u64 = 0x9fc00;
const MP_FLOATING_POINTER_GPA: u64 = EBDA_GPA + 16;
const MP_CONFIG_TABLE_GPA: u64 = MP_FLOATING_POINTER_GPA + 16;

/// A Linux e820 RAM extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct E820Entry {
    /// Start physical address.
    pub address: u64,
    /// Length in bytes.
    pub size: u64,
    /// Linux e820 memory type.
    pub memory_type: u32,
}

/// Builds the e820 RAM layout used by Linux.
pub fn e820_layout(mem_mib: u64) -> Vec<E820Entry> {
    let bytes = mem_mib.saturating_mul(1024 * 1024);
    let mut entries = vec![
        E820Entry {
            address: 0,
            size: 0x9fc00,
            memory_type: E820_RAM,
        },
        E820Entry {
            address: 0x100000,
            size: bytes.min(3 * 1024 * 1024 * 1024).saturating_sub(0x100000),
            memory_type: E820_RAM,
        },
    ];
    if bytes > 3 * 1024 * 1024 * 1024 {
        entries.push(E820Entry {
            address: 4 * 1024 * 1024 * 1024,
            size: bytes - 3 * 1024 * 1024 * 1024,
            memory_type: E820_RAM,
        });
    }
    entries
}

/// Loads an x86_64 ELF kernel into guest RAM and returns its entry point.
pub fn load_elf_kernel(path: &std::path::Path, memory: &GuestMemory) -> Result<u64> {
    let image = fs::read(path)
        .map_err(|error| UhvmError::new(format!("read kernel {}: {error}", path.display())))?;
    if image.get(0..4) != Some(b"\x7fELF")
        || image.get(4).copied() != Some(2)
        || image.get(5).copied() != Some(1)
        || read_u16(&image, 18)? != 62
    {
        return Err(UhvmError::new(
            "kernel is not a little-endian ELF64 x86_64 image",
        ));
    }
    let entry = read_u64(&image, 24)?;
    let program_offset = read_u64(&image, 32)?;
    let program_entry_size = read_u16(&image, 54)? as u64;
    let program_count = read_u16(&image, 56)? as u64;
    if program_entry_size < 56 {
        return Err(UhvmError::new("ELF program header is too small"));
    }
    let mut loaded_segments = 0_u64;
    let mut entry_is_loaded = false;
    for index in 0..program_count {
        let header_offset = program_offset
            .checked_add(
                index
                    .checked_mul(program_entry_size)
                    .ok_or_else(|| UhvmError::new("ELF program header offset overflows"))?,
            )
            .ok_or_else(|| UhvmError::new("ELF program header offset overflows"))?;
        let header = usize::try_from(header_offset)
            .map_err(|_| UhvmError::new("ELF program header offset is out of range"))?;
        let kind = read_u32(&image, header)?;
        if kind != 1 {
            continue;
        }
        let file_offset = read_u64(&image, header + 8)?;
        let guest_address = read_u64(&image, header + 24)?;
        let file_size = read_u64(&image, header + 32)?;
        let memory_size = read_u64(&image, header + 40)?;
        if file_size > memory_size {
            return Err(UhvmError::new("ELF segment file size exceeds memory size"));
        }
        if memory_size == 0 {
            continue;
        }
        let file_end = file_offset
            .checked_add(file_size)
            .and_then(|end| usize::try_from(end).ok())
            .ok_or_else(|| UhvmError::new("ELF segment file range overflows"))?;
        let file_start = usize::try_from(file_offset)
            .map_err(|_| UhvmError::new("ELF segment file offset is out of range"))?;
        let contents = image
            .get(file_start..file_end)
            .ok_or_else(|| UhvmError::new("ELF segment extends beyond kernel file"))?;
        let segment_size =
            usize::try_from(memory_size).map_err(|_| UhvmError::new("ELF segment is too large"))?;
        if !memory.contains_range(guest_address, segment_size) {
            return Err(UhvmError::new(format!(
                "ELF segment range {guest_address:#x}+{memory_size:#x} is outside guest RAM"
            )));
        }
        memory.write_at(guest_address, contents)?;
        loaded_segments += 1;
        entry_is_loaded |= entry >= guest_address
            && entry
                .checked_sub(guest_address)
                .is_some_and(|offset| offset < memory_size);
        if memory_size > file_size {
            let zero_start = guest_address
                .checked_add(file_size)
                .ok_or_else(|| UhvmError::new("ELF segment GPA overflows"))?;
            let zero_len = usize::try_from(memory_size - file_size)
                .map_err(|_| UhvmError::new("ELF zero-fill length is too large"))?;
            let zeroes = [0_u8; 64 * 1024];
            let mut written = 0_usize;
            while written < zero_len {
                let chunk_length = (zero_len - written).min(zeroes.len());
                let address = zero_start
                    .checked_add(written as u64)
                    .ok_or_else(|| UhvmError::new("ELF zero-fill address overflows"))?;
                memory.write_at(address, &zeroes[..chunk_length])?;
                written += chunk_length;
            }
        }
    }
    if loaded_segments == 0 || !entry_is_loaded || !memory.contains_range(entry, 1) {
        return Err(UhvmError::new(
            "ELF image has no loadable segment containing its entry point",
        ));
    }
    Ok(entry)
}

/// Writes Linux boot parameters, cmdline, and identity-mapped long-mode tables.
pub fn prepare_boot(memory: &GuestMemory, mem_mib: u64, cmdline: &str) -> Result<()> {
    let mut params = vec![0_u8; 4096];
    put_u16(&mut params, 0x1fe, 0xaa55);
    params[0x202..0x206].copy_from_slice(b"HdrS");
    put_u16(&mut params, 0x206, 0x020c);
    params[0x210] = 0xff;
    params[0x211] = 1;
    put_u32(&mut params, 0x228, CMDLINE_GPA as u32);
    put_u32(&mut params, 0x230, 0x0100_0000);
    put_u16(&mut params, 0x236, 1);
    put_u32(&mut params, 0x238, 4096);
    let entries = e820_layout(mem_mib);
    if entries.len() > E820_MAX_ENTRIES {
        return Err(UhvmError::new("e820 layout has too many entries"));
    }
    params[0x1e8] = entries.len() as u8;
    for (index, entry) in entries.iter().enumerate() {
        let offset = 0x2d0 + index * 20;
        put_u64(&mut params, offset, entry.address);
        put_u64(&mut params, offset + 8, entry.size);
        put_u32(&mut params, offset + 16, entry.memory_type);
    }
    memory.write_at(BOOT_PARAMS_GPA, &params)?;
    let cmdline_bytes = cmdline.as_bytes();
    if cmdline_bytes.len() >= 4096 {
        return Err(UhvmError::new("kernel command line exceeds 4095 bytes"));
    }
    memory.write_at(CMDLINE_GPA, cmdline_bytes)?;
    memory.write_obj(CMDLINE_GPA + cmdline_bytes.len() as u64, 0_u8)?;
    memory.write_obj(GDT_GPA, 0_u64)?;
    memory.write_obj(GDT_GPA + 8, 0x00af_9b00_0000_ffff_u64)?;
    memory.write_obj(GDT_GPA + 16, 0x00cf_9300_0000_ffff_u64)?;
    let tss_low = 0x0000_0000_0000_0067_u64 | (0x8b_u64 << 40);
    memory.write_obj(GDT_GPA + 24, tss_low)?;
    memory.write_obj(GDT_GPA + 32, 0_u64)?;
    for index in 0..512_u64 {
        let entry = (index * 0x20_0000) | 0x83;
        memory.write_obj(PD_GPA + index * 8, entry)?;
    }
    memory.write_obj(PML4_GPA, PDPT_GPA | 0x3)?;
    memory.write_obj(PDPT_GPA, PD_GPA | 0x3)?;
    Ok(())
}

/// Writes an Intel MP 1.4 floating pointer and configuration table for the guest CPUs.
pub fn write_mp_table(memory: &GuestMemory, vcpus: u8) -> Result<()> {
    if vcpus == 0 {
        return Err(UhvmError::new("MP table requires at least one CPU"));
    }
    let (floating_pointer, config_table) = build_mp_table(vcpus);
    memory.write_obj(BDA_EBDA_SEGMENT_GPA, 0x9fc0_u16)?;
    memory.write_obj(BDA_MEMORY_KIB_GPA, 0x27f_u16)?;
    memory.write_at(EBDA_GPA, &[1])?;
    memory.write_at(MP_FLOATING_POINTER_GPA, &floating_pointer)?;
    memory.write_at(MP_CONFIG_TABLE_GPA, &config_table)
}

fn build_mp_table(vcpus: u8) -> (Vec<u8>, Vec<u8>) {
    let mut entries = Vec::new();
    for cpu in 0..vcpus {
        entries.extend_from_slice(&[0, cpu, 0x14, 1 | if cpu == 0 { 2 } else { 0 }]);
        entries.extend_from_slice(&0x0000_0600_u32.to_le_bytes());
        entries.extend_from_slice(&0x0000_0201_u32.to_le_bytes());
        entries.extend_from_slice(&[0; 8]);
    }
    entries.extend_from_slice(&[1, 0]);
    entries.extend_from_slice(b"ISA   ");
    entries.extend_from_slice(&[2, vcpus, 0x14, 1]);
    entries.extend_from_slice(&0xfec0_0000_u32.to_le_bytes());
    for irq in 0..16_u8 {
        entries.extend_from_slice(&[3, 0, 0, irq, vcpus, irq]);
    }
    entries.extend_from_slice(&[4, 3, 0, 0, 0xff, 0]);
    entries.extend_from_slice(&[4, 1, 0, 0, 0xff, 1]);

    let total_length = 44 + entries.len();
    let mut config = vec![0_u8; 44];
    config[0..4].copy_from_slice(b"PCMP");
    config[4..6].copy_from_slice(&(total_length as u16).to_le_bytes());
    config[6] = 4;
    config[8..16].copy_from_slice(b"UHOST   ");
    config[16..28].copy_from_slice(b"UHVM        ");
    let entry_count = u16::from(vcpus) + 20;
    config[34..36].copy_from_slice(&entry_count.to_le_bytes());
    config[36..40].copy_from_slice(&0xfee0_0000_u32.to_le_bytes());
    config.extend_from_slice(&entries);
    config[7] = checksum(&config);

    let mut floating = vec![0_u8; 16];
    floating[0..4].copy_from_slice(b"_MP_");
    floating[4..8].copy_from_slice(&(MP_CONFIG_TABLE_GPA as u32).to_le_bytes());
    floating[8] = 1;
    floating[9] = 4;
    floating[10] = checksum(&floating);
    (floating, config)
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
        .wrapping_neg()
}

/// Initializes vCPU zero in 64-bit Linux boot protocol state.
pub fn configure_boot_vcpu(vcpu: &VcpuFd, entry: u64) -> Result<()> {
    let mut sregs = vcpu
        .get_sregs()
        .map_err(|error| UhvmError::new(format!("read vCPU special registers: {error}")))?;
    sregs.gdt.base = GDT_GPA;
    sregs.gdt.limit = 39;
    sregs.idt.base = 0;
    sregs.idt.limit = 0;
    sregs.cr3 = PML4_GPA;
    sregs.cr4 |= 1 << 5;
    sregs.cr0 |= 1 | (1 << 31);
    sregs.efer |= (1 << 8) | (1 << 10);
    sregs.cs = kvm_segment {
        base: 0,
        limit: u32::MAX,
        selector: 8,
        type_: 11,
        present: 1,
        dpl: 0,
        db: 0,
        s: 1,
        l: 1,
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    };
    let data_segment = kvm_segment {
        base: 0,
        limit: u32::MAX,
        selector: 16,
        type_: 3,
        present: 1,
        dpl: 0,
        db: 0,
        s: 1,
        l: 0,
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    };
    sregs.ds = data_segment;
    sregs.es = data_segment;
    sregs.fs = data_segment;
    sregs.gs = data_segment;
    sregs.ss = data_segment;
    sregs.tr = kvm_segment {
        base: 0,
        limit: 0x67,
        selector: 24,
        type_: 11,
        present: 1,
        dpl: 0,
        db: 0,
        s: 0,
        l: 0,
        g: 0,
        avl: 0,
        unusable: 0,
        padding: 0,
    };
    vcpu.set_sregs(&sregs)
        .map_err(|error| UhvmError::new(format!("set vCPU special registers: {error}")))?;
    vcpu.set_regs(&kvm_regs {
        rip: entry,
        rsp: 0x8ff0,
        rbp: 0x8ff0,
        rsi: BOOT_PARAMS_GPA,
        rflags: 2,
        ..kvm_regs::default()
    })
    .map_err(|error| UhvmError::new(format!("set vCPU registers: {error}")))?;
    let fpu = kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..kvm_fpu::default()
    };
    vcpu.set_fpu(&fpu)
        .map_err(|error| UhvmError::new(format!("set vCPU FPU state: {error}")))?;
    let msrs = [
        0x174,
        0x175,
        0x176,
        0x10,
        0x1a0,
        0xc000_0081,
        0xc000_0082,
        0xc000_0083,
        0xc000_0084,
        0xc000_0101,
    ]
    .into_iter()
    .map(|index| kvm_msr_entry {
        index,
        data: if index == 0x1a0 { 1 } else { 0 },
        ..kvm_msr_entry::default()
    })
    .collect::<Vec<_>>();
    let msrs = Msrs::from_entries(&msrs)
        .map_err(|error| UhvmError::new(format!("create vCPU MSR set: {error}")))?;
    let count = vcpu
        .set_msrs(&msrs)
        .map_err(|error| UhvmError::new(format!("set vCPU MSRs: {error}")))?;
    if count != msrs.as_slice().len() {
        return Err(UhvmError::new(
            "KVM accepted only part of the vCPU MSR list",
        ));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| UhvmError::new("ELF header is truncated"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| UhvmError::new("ELF header is truncated"))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes
        .get(offset..offset.saturating_add(8))
        .ok_or_else(|| UhvmError::new("ELF header is truncated"))?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{build_mp_table, e820_layout, load_elf_kernel, write_mp_table};
    use crate::sys::memory::GuestMemory;

    #[test]
    fn e820_layout_matches_256_mib() {
        let entries = e820_layout(256);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].address, 0);
        assert_eq!(entries[0].size, 0x9fc00);
        assert_eq!(entries[1].address, 0x100000);
        assert_eq!(entries[1].size, 255 * 1024 * 1024);
    }

    #[test]
    fn e820_layout_maps_four_gib_across_mmio_hole() {
        let entries = e820_layout(4096);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[1].size, 3 * 1024 * 1024 * 1024 - 0x100000);
        assert_eq!(entries[2].address, 4 * 1024 * 1024 * 1024);
        assert_eq!(entries[2].size, 1024 * 1024 * 1024);
    }

    #[test]
    fn elf_loader_rejects_segments_outside_ram() -> Result<(), Box<dyn Error>> {
        let memory = GuestMemory::new(1)?;
        let mut image = vec![0_u8; 0x110];
        image[0..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[18..20].copy_from_slice(&62_u16.to_le_bytes());
        image[24..32].copy_from_slice(&0x1000_u64.to_le_bytes());
        image[32..40].copy_from_slice(&64_u64.to_le_bytes());
        image[54..56].copy_from_slice(&56_u16.to_le_bytes());
        image[56..58].copy_from_slice(&1_u16.to_le_bytes());
        image[64..68].copy_from_slice(&1_u32.to_le_bytes());
        image[72..80].copy_from_slice(&0x100_u64.to_le_bytes());
        image[88..96].copy_from_slice(&0x200000_u64.to_le_bytes());
        image[96..104].copy_from_slice(&1_u64.to_le_bytes());
        image[104..112].copy_from_slice(&1_u64.to_le_bytes());
        let path = std::env::temp_dir().join(format!(
            "uhvm-elf-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        std::fs::write(&path, image)?;
        assert!(load_elf_kernel(&path, &memory).is_err());
        std::fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn mp_table_checksums_are_zero() {
        let (floating, config) = build_mp_table(2);
        assert_eq!(
            floating
                .iter()
                .fold(0_u8, |sum, byte| sum.wrapping_add(*byte)),
            0
        );
        assert_eq!(
            config
                .iter()
                .fold(0_u8, |sum, byte| sum.wrapping_add(*byte)),
            0
        );
    }

    #[test]
    fn mp_table_is_discoverable_through_the_bios_data_area() -> Result<(), Box<dyn Error>> {
        let memory = GuestMemory::new(16)?;
        write_mp_table(&memory, 2)?;
        assert_eq!(memory.read_obj::<u16>(0x40e)?, 0x9fc0);
        assert_eq!(memory.read_obj::<u16>(0x413)?, 0x27f);
        assert_eq!(memory.read_obj::<u8>(0x9fc00)?, 1);
        assert_eq!(memory.read_obj::<u32>(0x9fc14)?, 0x9fc20);
        Ok(())
    }
}
