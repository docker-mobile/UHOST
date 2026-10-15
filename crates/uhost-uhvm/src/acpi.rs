use crate::{Result, UhvmError, sys::memory::GuestMemory};

const RSDP_GPA: u64 = 0xe0000;
const RSDT_GPA: u64 = 0xe0040;
const XSDT_GPA: u64 = 0xe0080;
const FADT_GPA: u64 = 0xe0100;
const MADT_GPA: u64 = 0xe0300;
const DSDT_GPA: u64 = 0xe1000;
const FADT_LENGTH: usize = 276;
const MADT_LAPIC_GPA: u32 = 0xfee0_0000;
const IOAPIC_GPA: u32 = 0xfec0_0000;
const IOAPIC_IRQ_BASE: u32 = 0;
const VIRTIO_MMIO_BASE: u32 = 0xd000_0000;
const VIRTIO_MMIO_STRIDE: u32 = 0x1000;
const VIRTIO_MMIO_SIZE: u32 = 0x1000;

struct Tables {
    rsdp: Vec<u8>,
    rsdt: Vec<u8>,
    xsdt: Vec<u8>,
    fadt: Vec<u8>,
    madt: Vec<u8>,
    dsdt: Vec<u8>,
}

pub(super) fn write_tables(memory: &GuestMemory, vcpus: u8, drive_count: usize) -> Result<()> {
    if vcpus == 0 || vcpus > 8 {
        return Err(UhvmError::new("ACPI tables require between 1 and 8 CPUs"));
    }
    if drive_count == 0 || drive_count > 11 {
        return Err(UhvmError::new(
            "ACPI tables require between 1 and 11 virtio block devices",
        ));
    }

    let tables = build_tables(vcpus, drive_count);
    memory.write_at(RSDP_GPA, &tables.rsdp)?;
    memory.write_at(RSDT_GPA, &tables.rsdt)?;
    memory.write_at(XSDT_GPA, &tables.xsdt)?;
    memory.write_at(FADT_GPA, &tables.fadt)?;
    memory.write_at(MADT_GPA, &tables.madt)?;
    memory.write_at(DSDT_GPA, &tables.dsdt)
}

fn build_tables(vcpus: u8, drive_count: usize) -> Tables {
    let dsdt = build_dsdt(drive_count);
    let fadt = build_fadt();
    let madt = build_madt(vcpus);
    let entries = [FADT_GPA, MADT_GPA];
    let rsdt = build_root_table(*b"RSDT", 1, &entries, 4);
    let xsdt = build_root_table(*b"XSDT", 1, &entries, 8);
    let rsdp = build_rsdp();
    Tables {
        rsdp,
        rsdt,
        xsdt,
        fadt,
        madt,
        dsdt,
    }
}

fn build_rsdp() -> Vec<u8> {
    let mut rsdp = vec![0_u8; 36];
    let length = rsdp.len() as u32;
    rsdp[0..8].copy_from_slice(b"RSD PTR ");
    rsdp[9..15].copy_from_slice(b"UHOST ");
    rsdp[15] = 2;
    rsdp[16..20].copy_from_slice(&(RSDT_GPA as u32).to_le_bytes());
    rsdp[20..24].copy_from_slice(&length.to_le_bytes());
    rsdp[24..32].copy_from_slice(&XSDT_GPA.to_le_bytes());
    let first_checksum = checksum(&rsdp[..20]);
    rsdp[8] = first_checksum;
    let extended_checksum = checksum(&rsdp);
    rsdp[32] = extended_checksum;
    rsdp
}

fn build_root_table(
    signature: [u8; 4],
    revision: u8,
    entries: &[u64],
    pointer_width: usize,
) -> Vec<u8> {
    let length = 36 + entries.len() * pointer_width;
    let mut table = table_header(signature, revision, length);
    for (index, entry) in entries.iter().enumerate() {
        let offset = 36 + index * pointer_width;
        if pointer_width == 4 {
            table[offset..offset + 4].copy_from_slice(&(*entry as u32).to_le_bytes());
        } else {
            table[offset..offset + 8].copy_from_slice(&entry.to_le_bytes());
        }
    }
    finalize_table(&mut table);
    table
}

fn build_fadt() -> Vec<u8> {
    let mut fadt = table_header(*b"FACP", 6, FADT_LENGTH);
    fadt[40..44].copy_from_slice(&(DSDT_GPA as u32).to_le_bytes());
    fadt[45] = 4;
    fadt[112..116].copy_from_slice(&((1_u32 << 20) | (1 << 2)).to_le_bytes());
    fadt[140..148].copy_from_slice(&DSDT_GPA.to_le_bytes());
    finalize_table(&mut fadt);
    fadt
}

fn build_madt(vcpus: u8) -> Vec<u8> {
    let mut entries = Vec::new();
    for cpu_id in 0..vcpus {
        entries.extend_from_slice(&[0, 8, cpu_id, cpu_id]);
        entries.extend_from_slice(&1_u32.to_le_bytes());
    }
    entries.extend_from_slice(&[1, 12, vcpus, 0]);
    entries.extend_from_slice(&IOAPIC_GPA.to_le_bytes());
    entries.extend_from_slice(&IOAPIC_IRQ_BASE.to_le_bytes());
    entries.extend_from_slice(&[2, 10, 0, 0]);
    entries.extend_from_slice(&2_u32.to_le_bytes());
    entries.extend_from_slice(&0_u16.to_le_bytes());

    let length = 44 + entries.len();
    let mut madt = table_header(*b"APIC", 1, length);
    madt[36..40].copy_from_slice(&MADT_LAPIC_GPA.to_le_bytes());
    madt[40..44].copy_from_slice(&1_u32.to_le_bytes());
    madt[44..].copy_from_slice(&entries);
    finalize_table(&mut madt);
    madt
}

fn build_dsdt(drive_count: usize) -> Vec<u8> {
    let mut namespace = vec![0x5c, b'_', b'S', b'B', b'_'];
    namespace.extend_from_slice(&build_serial_device());
    for index in 0..drive_count {
        namespace.extend_from_slice(&build_virtio_device(index));
    }
    let scope = package(&[0x10], &namespace);
    let mut dsdt = table_header(*b"DSDT", 2, 36 + scope.len());
    dsdt[36..].copy_from_slice(&scope);
    finalize_table(&mut dsdt);
    dsdt
}

fn build_serial_device() -> Vec<u8> {
    let mut terms = vec![0x08, b'_', b'H', b'I', b'D', 0x0c, 0x41, 0xd0, 0x05, 0x01];
    terms.extend_from_slice(&[0x08, b'_', b'U', b'I', b'D']);
    append_integer(&mut terms, 0);
    terms.extend_from_slice(&[0x08, b'_', b'C', b'R', b'S']);

    let resources = [
        0x47, 0x01, 0xf8, 0x03, 0xf8, 0x03, 0x00, 0x08, 0x89, 0x06, 0x00, 0x03, 0x01, 0x04, 0x00,
        0x00, 0x00, 0x79, 0x00,
    ];
    let mut buffer = vec![0x0a, resources.len() as u8];
    buffer.extend_from_slice(&resources);
    terms.extend_from_slice(&package(&[0x11], &buffer));

    let mut body = b"COM1".to_vec();
    body.extend_from_slice(&terms);
    package(&[0x5b, 0x82], &body)
}

fn build_virtio_device(index: usize) -> Vec<u8> {
    let mut terms = Vec::new();
    terms.extend_from_slice(&[0x08, b'_', b'H', b'I', b'D', 0x0d]);
    terms.extend_from_slice(b"LNRO0005\0");
    terms.extend_from_slice(&[0x08, b'_', b'U', b'I', b'D']);
    append_integer(&mut terms, index as u64);
    terms.extend_from_slice(&[0x08, b'_', b'C', b'R', b'S']);

    let base = VIRTIO_MMIO_BASE + (index as u32) * VIRTIO_MMIO_STRIDE;
    let mut resources = vec![0x86, 9, 0, 1];
    resources.extend_from_slice(&base.to_le_bytes());
    resources.extend_from_slice(&VIRTIO_MMIO_SIZE.to_le_bytes());
    resources.extend_from_slice(&[0x89, 6, 0, 2, 1]);
    resources.extend_from_slice(&(5 + index as u32).to_le_bytes());
    resources.extend_from_slice(&[0x79, 0]);

    let mut buffer = vec![0x0a, resources.len() as u8];
    buffer.extend_from_slice(&resources);
    terms.extend_from_slice(&package(&[0x11], &buffer));

    let device_number = if index < 10 {
        b'0' + index as u8
    } else {
        b'A' + (index - 10) as u8
    };
    let mut body = vec![b'V', b'I', b'R', device_number];
    body.extend_from_slice(&terms);
    package(&[0x5b, 0x82], &body)
}

fn append_integer(output: &mut Vec<u8>, value: u64) {
    match value {
        0 => output.push(0x00),
        1 => output.push(0x01),
        value if value <= u64::from(u8::MAX) => {
            output.extend_from_slice(&[0x0a, value as u8]);
        }
        value => {
            output.push(0x0e);
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
}

fn package(opcode: &[u8], body: &[u8]) -> Vec<u8> {
    let mut package_length = body.len() + 1;
    let mut encoded_length = encode_package_length(package_length);
    while encoded_length.len() + body.len() != package_length {
        package_length = encoded_length.len() + body.len();
        encoded_length = encode_package_length(package_length);
    }
    let mut output = Vec::with_capacity(opcode.len() + package_length);
    output.extend_from_slice(opcode);
    output.extend_from_slice(&encoded_length);
    output.extend_from_slice(body);
    output
}

fn encode_package_length(length: usize) -> Vec<u8> {
    let follow_bytes = if length <= 0x3f {
        0
    } else if length <= 0x0fff {
        1
    } else if length <= 0x0f_ffff {
        2
    } else {
        3
    };
    let mut encoded = Vec::with_capacity(follow_bytes + 1);
    let low_bits = if follow_bytes == 0 {
        length as u8
    } else {
        (length & 0x0f) as u8
    };
    encoded.push(((follow_bytes as u8) << 6) | low_bits);
    for index in 0..follow_bytes {
        encoded.push((length >> (4 + index * 8)) as u8);
    }
    encoded
}

fn table_header(signature: [u8; 4], revision: u8, length: usize) -> Vec<u8> {
    let mut table = vec![0_u8; length];
    table[0..4].copy_from_slice(&signature);
    table[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    table[8] = revision;
    table[10..16].copy_from_slice(b"UHOST ");
    table[16..24].copy_from_slice(b"UHVM    ");
    table[24..28].copy_from_slice(&1_u32.to_le_bytes());
    table[28..32].copy_from_slice(b"RUST");
    table[32..36].copy_from_slice(&1_u32.to_le_bytes());
    table
}

fn finalize_table(table: &mut [u8]) {
    table[9] = checksum(table);
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
        .wrapping_neg()
}

#[cfg(test)]
mod tests {
    use super::{build_tables, encode_package_length};

    #[test]
    fn acpi_tables_have_valid_checksums_and_virtio_devices() {
        let tables = build_tables(2, 1);
        for table in [
            &tables.rsdt,
            &tables.xsdt,
            &tables.fadt,
            &tables.madt,
            &tables.dsdt,
        ] {
            assert_eq!(
                table.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte)),
                0
            );
        }
        assert_eq!(tables.rsdp[0..8], *b"RSD PTR ");
        assert_eq!(
            tables.rsdp[..20]
                .iter()
                .fold(0_u8, |sum, byte| sum.wrapping_add(*byte)),
            0
        );
        assert_eq!(
            tables
                .rsdp
                .iter()
                .fold(0_u8, |sum, byte| sum.wrapping_add(*byte)),
            0
        );
        assert!(tables.dsdt.windows(8).any(|bytes| bytes == b"LNRO0005"));
        assert!(
            tables
                .dsdt
                .windows(4)
                .any(|bytes| bytes == 0xd000_0000_u32.to_le_bytes())
        );
        assert!(tables.dsdt.windows(4).any(|bytes| bytes == b"COM1"));
        assert!(tables.dsdt.windows(10).any(|bytes| {
            bytes == [0x08, b'_', b'H', b'I', b'D', 0x0c, 0x41, 0xd0, 0x05, 0x01]
        }));
        assert!(
            tables
                .dsdt
                .windows(8)
                .any(|bytes| bytes == [0x47, 0x01, 0xf8, 0x03, 0xf8, 0x03, 0x00, 0x08])
        );
        assert!(
            tables
                .dsdt
                .windows(9)
                .any(|bytes| bytes == [0x89, 0x06, 0x00, 0x03, 0x01, 0x04, 0x00, 0x00, 0x00])
        );
    }

    #[test]
    #[ignore = "used to dump the DSDT for an iasl disassembly check"]
    fn dump_dsdt_for_iasl() -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::var("UHVM_TEST_DSDT_PATH")?;
        std::fs::write(path, build_tables(2, 1).dsdt)?;
        Ok(())
    }

    #[test]
    fn aml_package_lengths_encode_single_and_multiple_bytes() {
        assert_eq!(encode_package_length(26), [26]);
        assert_eq!(encode_package_length(66), [0x42, 0x04]);
    }
}
