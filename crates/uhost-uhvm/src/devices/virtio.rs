use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    sync::Mutex,
};

use vmm_sys_util::eventfd::EventFd;

use crate::{Result, UhvmError, sys::memory::GuestMemory};

const QUEUE_MAX: u16 = 128;
const DESC_NEXT: u16 = 1;
const DESC_WRITE: u16 = 2;
const DESC_INDIRECT: u16 = 4;
const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;
const VIRTIO_BLK_T_GET_ID: u32 = 8;
const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;
const VIRTIO_F_VERSION_1: u64 = 1 << 32;
const VIRTIO_BLK_F_RO: u64 = 1 << 5;
const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;

#[derive(Debug, Clone, Copy)]
struct Descriptor {
    address: u64,
    length: u32,
    flags: u16,
}

#[derive(Debug, Default)]
struct Queue {
    size: u16,
    ready: bool,
    descriptor_address: u64,
    available_address: u64,
    used_address: u64,
    last_available: u16,
    used_index: u16,
}

/// Modern virtio-mmio block device backed by a raw image.
pub struct VirtioBlock {
    file: Mutex<File>,
    read_only: bool,
    capacity_sectors: u64,
    irq: EventFd,
    queue: Queue,
    status: u32,
    device_feature_select: u32,
    driver_feature_select: u32,
    driver_features: u64,
    queue_select: u32,
    interrupt_status: u32,
    config_generation: u32,
}

impl VirtioBlock {
    /// Opens a raw image and initializes the transport.
    pub fn open(path: &Path, read_only: bool, irq: EventFd) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(!read_only);
        let file = options
            .open(path)
            .map_err(|error| UhvmError::new(format!("open drive {}: {error}", path.display())))?;
        let capacity_sectors = file
            .metadata()
            .map_err(|error| UhvmError::new(format!("stat drive {}: {error}", path.display())))?
            .len()
            / 512;
        Ok(Self {
            file: Mutex::new(file),
            read_only,
            capacity_sectors,
            irq,
            queue: Queue::default(),
            status: 0,
            device_feature_select: 0,
            driver_feature_select: 0,
            driver_features: 0,
            queue_select: 0,
            interrupt_status: 0,
            config_generation: 0,
        })
    }

    /// Handles a 32-bit guest MMIO read.
    pub fn read_register(&self, offset: u64) -> u32 {
        match offset {
            0x000 => 0x7472_6976,
            0x004 => 2,
            0x008 => 2,
            0x00c => 0x5548_4f53,
            0x010 => self.host_features(),
            0x014 => self.device_feature_select,
            0x020 => self.driver_features as u32,
            0x024 => self.driver_feature_select,
            0x030 => self.queue_select,
            0x034 => u32::from(self.queue_select == 0) * u32::from(QUEUE_MAX),
            0x038 => u32::from(self.queue.size),
            0x044 => u32::from(self.queue.ready),
            0x060 => self.interrupt_status,
            0x070 => self.status,
            0x080 => self.queue.descriptor_address as u32,
            0x084 => (self.queue.descriptor_address >> 32) as u32,
            0x090 => self.queue.available_address as u32,
            0x094 => (self.queue.available_address >> 32) as u32,
            0x0a0 => self.queue.used_address as u32,
            0x0a4 => (self.queue.used_address >> 32) as u32,
            0x0fc => self.config_generation,
            0x100 => self.capacity_sectors as u32,
            0x104 => (self.capacity_sectors >> 32) as u32,
            _ => 0,
        }
    }

    /// Handles a 32-bit guest MMIO write and any queue notifications.
    pub fn write_register(&mut self, offset: u64, value: u32, memory: &GuestMemory) -> Result<()> {
        match offset {
            0x014 => self.device_feature_select = value,
            0x020 => {
                let shift = self.driver_feature_select.saturating_mul(32);
                if shift < 64 {
                    let mask = 0xffff_ffff_u64 << shift;
                    self.driver_features =
                        (self.driver_features & !mask) | (u64::from(value) << shift);
                }
            }
            0x024 => self.driver_feature_select = value,
            0x030 => self.queue_select = value,
            0x038 if self.queue_select == 0 => {
                if self.queue.ready || value > u32::from(QUEUE_MAX) {
                    self.mark_needs_reset();
                } else {
                    self.queue.size = value as u16;
                }
            }
            0x044 if self.queue_select == 0 => {
                if value == 0 {
                    self.queue.ready = false;
                } else if self.queue.size == 0
                    || !self.queue.size.is_power_of_two()
                    || !self.queue_layout_valid(memory)
                {
                    self.mark_needs_reset();
                } else {
                    self.queue.ready = true;
                }
            }
            0x050 if self.queue_select == 0 => {
                if value == 0 && self.queue.ready && self.status & 0x40 == 0 {
                    self.process_queue(memory);
                }
            }
            0x064 => {
                self.interrupt_status &= !value;
            }
            0x070 => {
                if value == 0 {
                    self.status = 0;
                    self.queue = Queue::default();
                    self.driver_features = 0;
                    self.interrupt_status = 0;
                } else if value & 0x40 != 0 {
                    self.mark_needs_reset();
                } else {
                    self.status = value;
                }
            }
            0x080 if self.queue_select == 0 && self.queue.ready => self.mark_needs_reset(),
            0x080 if self.queue_select == 0 => set_low(&mut self.queue.descriptor_address, value),
            0x084 if self.queue_select == 0 && self.queue.ready => self.mark_needs_reset(),
            0x084 if self.queue_select == 0 => set_high(&mut self.queue.descriptor_address, value),
            0x090 if self.queue_select == 0 && self.queue.ready => self.mark_needs_reset(),
            0x090 if self.queue_select == 0 => set_low(&mut self.queue.available_address, value),
            0x094 if self.queue_select == 0 && self.queue.ready => self.mark_needs_reset(),
            0x094 if self.queue_select == 0 => set_high(&mut self.queue.available_address, value),
            0x0a0 if self.queue_select == 0 && self.queue.ready => self.mark_needs_reset(),
            0x0a0 if self.queue_select == 0 => set_low(&mut self.queue.used_address, value),
            0x0a4 if self.queue_select == 0 && self.queue.ready => self.mark_needs_reset(),
            0x0a4 if self.queue_select == 0 => set_high(&mut self.queue.used_address, value),
            _ => {}
        }
        Ok(())
    }

    fn host_features(&self) -> u32 {
        let features = VIRTIO_F_VERSION_1
            | VIRTIO_BLK_F_FLUSH
            | if self.read_only { VIRTIO_BLK_F_RO } else { 0 };
        if self.device_feature_select == 0 {
            features as u32
        } else if self.device_feature_select == 1 {
            (features >> 32) as u32
        } else {
            0
        }
    }

    fn queue_layout_valid(&self, memory: &GuestMemory) -> bool {
        let size = u64::from(self.queue.size);
        if !self.queue.descriptor_address.is_multiple_of(16)
            || !self.queue.available_address.is_multiple_of(2)
            || !self.queue.used_address.is_multiple_of(4)
        {
            return false;
        }
        let Some(descriptor_bytes) = size.checked_mul(16) else {
            return false;
        };
        let Some(available_bytes) = size.checked_mul(2).and_then(|n| n.checked_add(6)) else {
            return false;
        };
        let Some(used_bytes) = size.checked_mul(8).and_then(|n| n.checked_add(6)) else {
            return false;
        };
        memory.contains_range(self.queue.descriptor_address, descriptor_bytes as usize)
            && memory.contains_range(self.queue.available_address, available_bytes as usize)
            && memory.contains_range(self.queue.used_address, used_bytes as usize)
    }

    fn process_queue(&mut self, memory: &GuestMemory) {
        let available_index = match memory.read_obj::<u16>(self.queue.available_address + 2) {
            Ok(index) => index,
            Err(_) => {
                self.mark_needs_reset();
                return;
            }
        };
        let available_count = available_index.wrapping_sub(self.queue.last_available);
        if available_count > self.queue.size {
            self.mark_needs_reset();
            return;
        }
        while self.queue.last_available != available_index {
            let ring_slot = self.queue.last_available % self.queue.size;
            let ring_address = self.queue.available_address + 4 + u64::from(ring_slot) * 2;
            let head = match memory.read_obj::<u16>(ring_address) {
                Ok(head) if head < self.queue.size => head,
                _ => {
                    self.mark_needs_reset();
                    return;
                }
            };
            let used_length = match self.handle_request(memory, head) {
                Ok(length) => length,
                Err(_) => {
                    self.mark_needs_reset();
                    return;
                }
            };
            let used_slot = self.queue.used_index % self.queue.size;
            let used_entry = self.queue.used_address + 4 + u64::from(used_slot) * 8;
            if memory
                .write_obj(used_entry, u32::from(head))
                .and_then(|()| memory.write_obj(used_entry + 4, used_length))
                .is_err()
            {
                self.mark_needs_reset();
                return;
            }
            self.queue.used_index = self.queue.used_index.wrapping_add(1);
            if memory
                .write_obj(self.queue.used_address + 2, self.queue.used_index)
                .is_err()
            {
                self.mark_needs_reset();
                return;
            }
            self.queue.last_available = self.queue.last_available.wrapping_add(1);
            self.interrupt_status |= 1;
        }
        if self.interrupt_status & 1 != 0 {
            let _ = self.irq.write(1);
        }
    }

    fn handle_request(&mut self, memory: &GuestMemory, head: u16) -> Result<u32> {
        let chain = descriptor_chain(memory, &self.queue, head)?;
        if chain.len() < 2 {
            return Err(UhvmError::new("virtio-blk request chain is too short"));
        }
        let header = chain[0];
        let status_descriptor = *chain
            .last()
            .ok_or_else(|| UhvmError::new("virtio-blk status descriptor is missing"))?;
        if header.flags & DESC_WRITE != 0
            || status_descriptor.flags & DESC_WRITE == 0
            || status_descriptor.length < 1
            || header.length < 16
        {
            return Err(UhvmError::new(
                "invalid virtio-blk request header or status",
            ));
        }
        let request_type = memory.read_obj::<u32>(header.address)?;
        let sector = memory.read_obj::<u64>(header.address + 8)?;
        let data_descriptors = &chain[1..chain.len() - 1];
        let mut data_length = 0_u32;
        let mut status = VIRTIO_BLK_S_OK;
        match request_type {
            VIRTIO_BLK_T_IN => {
                let requested = data_descriptors.iter().try_fold(0_u64, |sum, desc| {
                    sum.checked_add(u64::from(desc.length))
                        .ok_or_else(|| UhvmError::new("virtio-blk request length overflows"))
                })?;
                let offset = sector
                    .checked_mul(512)
                    .ok_or_else(|| UhvmError::new("virtio-blk sector offset overflows"))?;
                let end = offset
                    .checked_add(requested)
                    .ok_or_else(|| UhvmError::new("virtio-blk read range overflows"))?;
                if end > self.capacity_sectors * 512 {
                    status = VIRTIO_BLK_S_IOERR;
                } else {
                    let mut bytes = vec![
                        0;
                        usize::try_from(requested).map_err(|_| UhvmError::new(
                            "virtio-blk request is too large"
                        ))?
                    ];
                    let mut file = self
                        .file
                        .lock()
                        .map_err(|_| UhvmError::new("virtio-blk file lock is poisoned"))?;
                    file.seek(SeekFrom::Start(offset))
                        .and_then(|_| file.read_exact(&mut bytes))
                        .map_err(|error| UhvmError::new(format!("read virtio block: {error}")))?;
                    let mut cursor = 0_usize;
                    for descriptor in data_descriptors {
                        let length = descriptor.length as usize;
                        if descriptor.flags & DESC_WRITE == 0 {
                            return Err(UhvmError::new("virtio-blk IN descriptor is not writable"));
                        }
                        memory.write_at(descriptor.address, &bytes[cursor..cursor + length])?;
                        cursor += length;
                    }
                    data_length = requested.min(u64::from(u32::MAX)) as u32;
                }
            }
            VIRTIO_BLK_T_OUT => {
                if self.read_only
                    || data_descriptors
                        .iter()
                        .any(|desc| desc.flags & DESC_WRITE != 0)
                {
                    status = VIRTIO_BLK_S_IOERR;
                } else {
                    let requested = data_descriptors.iter().try_fold(0_u64, |sum, desc| {
                        sum.checked_add(u64::from(desc.length))
                            .ok_or_else(|| UhvmError::new("virtio-blk request length overflows"))
                    })?;
                    let offset = sector
                        .checked_mul(512)
                        .ok_or_else(|| UhvmError::new("virtio-blk sector offset overflows"))?;
                    if offset
                        .checked_add(requested)
                        .is_none_or(|end| end > self.capacity_sectors * 512)
                    {
                        status = VIRTIO_BLK_S_IOERR;
                    } else {
                        let mut bytes = vec![
                            0;
                            usize::try_from(requested).map_err(|_| {
                                UhvmError::new("virtio-blk request is too large")
                            })?
                        ];
                        let mut cursor = 0_usize;
                        for descriptor in data_descriptors {
                            let length = descriptor.length as usize;
                            memory
                                .read_at(descriptor.address, &mut bytes[cursor..cursor + length])?;
                            cursor += length;
                        }
                        let mut file = self
                            .file
                            .lock()
                            .map_err(|_| UhvmError::new("virtio-blk file lock is poisoned"))?;
                        file.seek(SeekFrom::Start(offset))
                            .and_then(|_| file.write_all(&bytes))
                            .map_err(|error| {
                                UhvmError::new(format!("write virtio block: {error}"))
                            })?;
                    }
                }
            }
            VIRTIO_BLK_T_FLUSH => {
                if let Ok(file) = self.file.lock() {
                    if file.sync_all().is_err() {
                        status = VIRTIO_BLK_S_IOERR;
                    }
                } else {
                    status = VIRTIO_BLK_S_IOERR;
                }
            }
            VIRTIO_BLK_T_GET_ID => {
                let id = b"UHOST-UHVM-RUST\0\0\0\0\0";
                let Some(descriptor) = data_descriptors.first() else {
                    return Err(UhvmError::new("virtio-blk GET_ID has no data descriptor"));
                };
                if descriptor.flags & DESC_WRITE == 0 {
                    return Err(UhvmError::new(
                        "virtio-blk GET_ID descriptor is not writable",
                    ));
                }
                let length = (descriptor.length as usize).min(id.len());
                memory.write_at(descriptor.address, &id[..length])?;
                data_length = length as u32;
            }
            _ => status = VIRTIO_BLK_S_UNSUPP,
        }
        memory.write_obj(status_descriptor.address, status)?;
        Ok(data_length.saturating_add(1))
    }

    fn mark_needs_reset(&mut self) {
        self.status |= 0x40;
        self.interrupt_status |= 2;
        let _ = self.irq.write(1);
    }
}

fn set_low(value: &mut u64, low: u32) {
    *value = (*value & 0xffff_ffff_0000_0000) | u64::from(low);
}

fn set_high(value: &mut u64, high: u32) {
    *value = (*value & 0x0000_0000_ffff_ffff) | (u64::from(high) << 32);
}

fn descriptor_chain(memory: &GuestMemory, queue: &Queue, head: u16) -> Result<Vec<Descriptor>> {
    if queue.size == 0 || head >= queue.size {
        return Err(UhvmError::new("virtqueue head index is out of range"));
    }
    let mut chain = Vec::new();
    let mut visited = vec![false; queue.size as usize];
    let mut index = head;
    loop {
        if index >= queue.size || visited[index as usize] || chain.len() >= queue.size as usize {
            return Err(UhvmError::new(
                "virtqueue descriptor chain loops or exceeds queue size",
            ));
        }
        visited[index as usize] = true;
        let descriptor_address = queue
            .descriptor_address
            .checked_add(
                u64::from(index)
                    .checked_mul(16)
                    .ok_or_else(|| UhvmError::new("virtqueue descriptor offset overflows"))?,
            )
            .ok_or_else(|| UhvmError::new("virtqueue descriptor address overflows"))?;
        let mut bytes = [0_u8; 16];
        memory.read_at(descriptor_address, &mut bytes)?;
        let address = u64::from_le_bytes(
            bytes[0..8]
                .try_into()
                .map_err(|_| UhvmError::new("virtqueue descriptor address field is malformed"))?,
        );
        let length = u32::from_le_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| UhvmError::new("virtqueue descriptor length field is malformed"))?,
        );
        let flags = u16::from_le_bytes([bytes[12], bytes[13]]);
        let next = u16::from_le_bytes([bytes[14], bytes[15]]);
        let _end = address
            .checked_add(u64::from(length))
            .ok_or_else(|| UhvmError::new("virtqueue descriptor range overflows"))?;
        if !memory.contains_range(address, length as usize) {
            return Err(UhvmError::new(
                "virtqueue descriptor range is outside guest RAM",
            ));
        }
        if flags & DESC_INDIRECT != 0 {
            return Err(UhvmError::new(
                "indirect virtqueue descriptors are unsupported",
            ));
        }
        if flags & !(DESC_NEXT | DESC_WRITE | DESC_INDIRECT) != 0 {
            return Err(UhvmError::new(
                "virtqueue descriptor has reserved flags set",
            ));
        }
        chain.push(Descriptor {
            address,
            length,
            flags,
        });
        if flags & DESC_NEXT == 0 {
            break;
        }
        index = next;
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{DESC_NEXT, Queue, descriptor_chain};
    use crate::sys::memory::GuestMemory;
    use vmm_sys_util::eventfd::EventFd;

    fn memory_with_chain(
        first_addr: u64,
        first_len: u32,
        first_flags: u16,
        next: u16,
    ) -> Result<GuestMemory, Box<dyn Error>> {
        let memory = GuestMemory::new(1)?;
        memory.write_obj(0x1000, first_addr)?;
        memory.write_obj(0x1008, first_len)?;
        memory.write_obj(0x100c, first_flags)?;
        memory.write_obj(0x100e, next)?;
        Ok(memory)
    }

    #[test]
    fn rejects_descriptor_address_overflow_and_out_of_ram() -> Result<(), Box<dyn Error>> {
        let memory = memory_with_chain(u64::MAX - 3, 8, 0, 0)?;
        let queue = Queue {
            size: 8,
            descriptor_address: 0x1000,
            ..Queue::default()
        };
        assert!(descriptor_chain(&memory, &queue, 0).is_err());
        let memory = memory_with_chain(0xfffff, 2, 0, 0)?;
        assert!(descriptor_chain(&memory, &queue, 0).is_err());
        Ok(())
    }

    #[test]
    fn rejects_loops_and_indices_outside_queue() -> Result<(), Box<dyn Error>> {
        let memory = memory_with_chain(0x2000, 1, DESC_NEXT, 0)?;
        let queue = Queue {
            size: 8,
            descriptor_address: 0x1000,
            ..Queue::default()
        };
        assert!(descriptor_chain(&memory, &queue, 0).is_err());
        assert!(descriptor_chain(&memory, &queue, 8).is_err());
        Ok(())
    }

    #[test]
    fn rejects_chain_that_exceeds_queue_size() -> Result<(), Box<dyn Error>> {
        let memory = GuestMemory::new(1)?;
        for index in 0..8_u64 {
            let address = 0x1000 + index * 16;
            memory.write_obj(address, 0x3000_u64 + index)?;
            memory.write_obj(address + 8, 1_u32)?;
            memory.write_obj(address + 12, DESC_NEXT)?;
            memory.write_obj(address + 14, ((index + 1) % 8) as u16)?;
        }
        let queue = Queue {
            size: 8,
            descriptor_address: 0x1000,
            ..Queue::default()
        };
        assert!(descriptor_chain(&memory, &queue, 0).is_err());
        Ok(())
    }

    #[test]
    fn rejects_available_indices_outside_queue() -> Result<(), Box<dyn Error>> {
        let memory = GuestMemory::new(1)?;
        let path = std::env::temp_dir().join(format!(
            "uhvm-virtio-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        std::fs::write(&path, b"")?;
        let mut device = super::VirtioBlock::open(&path, true, EventFd::new(0)?)?;
        device.queue = Queue {
            size: 8,
            ready: true,
            available_address: 0x1000,
            ..Queue::default()
        };
        memory.write_obj(0x1002, 9_u16)?;
        device.process_queue(&memory);
        assert_ne!(device.status & 0x40, 0);
        drop(device);
        std::fs::remove_file(path)?;
        Ok(())
    }
}
