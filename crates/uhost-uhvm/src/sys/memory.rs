//! Guarded guest RAM mappings and bounds-checked guest-memory access.

use std::{io, ptr::NonNull};

use crate::{Result, UhvmError};

const MMIO_HOLE_START: u64 = 3 * 1024 * 1024 * 1024;
const MMIO_HOLE_END: u64 = 4 * 1024 * 1024 * 1024;

/// One guest-physical RAM region backed by a guarded host mapping.
pub struct RamRegion {
    guest_address: u64,
    length: usize,
    mapping: NonNull<u8>,
    mapping_length: usize,
    page_size: usize,
}

impl RamRegion {
    /// Guest physical base address of this region.
    pub const fn guest_address(&self) -> u64 {
        self.guest_address
    }

    /// Region length in bytes.
    pub const fn len(&self) -> u64 {
        self.length as u64
    }

    /// Whether this region is empty.
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Host pointer used by KVM for this region.
    pub fn host_address(&self) -> u64 {
        // SAFETY: the mapping remains valid for the lifetime of RamRegion.
        unsafe { self.mapping.as_ptr().add(self.page_size) as u64 }
    }

    fn contains(&self, address: u64, length: usize) -> bool {
        let Some(end) = address.checked_add(length as u64) else {
            return false;
        };
        let Some(region_end) = self.guest_address.checked_add(self.length as u64) else {
            return false;
        };
        address >= self.guest_address && end <= region_end
    }

    fn offset(&self, address: u64) -> usize {
        (address - self.guest_address) as usize
    }
}

impl Drop for RamRegion {
    fn drop(&mut self) {
        // SAFETY: mapping was returned by mmap and mapping_length is its exact size.
        unsafe {
            libc::munmap(self.mapping.as_ptr().cast(), self.mapping_length);
        }
    }
}

// SAFETY: access to the guest mapping is mediated through checked operations; KVM
// may update guest RAM concurrently, as required by the shared-memory ABI.
unsafe impl Send for RamRegion {}
// SAFETY: the mapping is stable and access is through the bounds-checked methods.
unsafe impl Sync for RamRegion {}

/// Guest RAM with an MMIO gap between 3 GiB and 4 GiB and guard pages.
pub struct GuestMemory {
    regions: Vec<RamRegion>,
}

impl GuestMemory {
    /// Creates guest RAM of `mem_mib` MiB.
    pub fn new(mem_mib: u64) -> Result<Self> {
        let bytes = mem_mib
            .checked_mul(1024 * 1024)
            .ok_or_else(|| UhvmError::new("guest memory size overflows"))?;
        if bytes == 0 {
            return Err(UhvmError::new("guest memory must be nonzero"));
        }
        let low_length = bytes.min(MMIO_HOLE_START);
        let mut regions = vec![map_region(0, low_length)?];
        if bytes > MMIO_HOLE_START {
            let high_length = bytes - MMIO_HOLE_START;
            regions.push(map_region(MMIO_HOLE_END, high_length)?);
        }
        Ok(Self { regions })
    }

    /// Iterates guest RAM regions in GPA order.
    pub fn regions(&self) -> impl Iterator<Item = &RamRegion> {
        self.regions.iter()
    }

    /// Returns whether the complete GPA range is backed by RAM.
    pub fn contains_range(&self, address: u64, length: usize) -> bool {
        self.regions
            .iter()
            .any(|region| region.contains(address, length))
    }

    /// Copies guest bytes into `destination`.
    pub fn read_at(&self, address: u64, destination: &mut [u8]) -> Result<()> {
        let region = self.region_for(address, destination.len())?;
        let offset = region.offset(address);
        for (index, byte) in destination.iter_mut().enumerate() {
            // SAFETY: region_for checked the complete range and the mapping remains
            // valid; volatile reads observe bytes that KVM may update asynchronously.
            *byte = unsafe {
                std::ptr::read_volatile(
                    region
                        .mapping
                        .as_ptr()
                        .add(region.page_size + offset + index),
                )
            };
        }
        Ok(())
    }

    /// Copies bytes into guest memory.
    pub fn write_at(&self, address: u64, source: &[u8]) -> Result<()> {
        let region = self.region_for(address, source.len())?;
        let offset = region.offset(address);
        for (index, byte) in source.iter().enumerate() {
            // SAFETY: region_for checked the complete range and the mapping remains
            // valid; volatile writes reach bytes that KVM may read asynchronously.
            unsafe {
                std::ptr::write_volatile(
                    region
                        .mapping
                        .as_ptr()
                        .add(region.page_size + offset + index),
                    *byte,
                );
            }
        }
        Ok(())
    }

    /// Reads a little-endian integer from guest RAM.
    pub fn read_obj<T: GuestValue>(&self, address: u64) -> Result<T> {
        let mut bytes = vec![0; T::SIZE];
        self.read_at(address, &mut bytes)?;
        Ok(T::decode(&bytes))
    }

    /// Writes a little-endian integer to guest RAM.
    pub fn write_obj<T: GuestValue>(&self, address: u64, value: T) -> Result<()> {
        let mut bytes = vec![0; T::SIZE];
        value.encode(&mut bytes);
        self.write_at(address, &bytes)
    }

    fn region_for(&self, address: u64, length: usize) -> Result<&RamRegion> {
        self.regions
            .iter()
            .find(|region| region.contains(address, length))
            .ok_or_else(|| {
                UhvmError::new(format!(
                    "guest memory range {address:#x}+{length:#x} is out of range"
                ))
            })
    }
}

/// Integer types supported by guest-memory object operations.
pub trait GuestValue: Copy {
    /// Size in bytes.
    const SIZE: usize;
    /// Decodes little-endian bytes.
    fn decode(bytes: &[u8]) -> Self;
    /// Encodes little-endian bytes into the destination.
    fn encode(self, bytes: &mut [u8]);
}

macro_rules! impl_guest_value {
    ($type:ty, $size:expr) => {
        impl GuestValue for $type {
            const SIZE: usize = $size;

            fn decode(bytes: &[u8]) -> Self {
                let mut array = [0; $size];
                array.copy_from_slice(bytes);
                <$type>::from_le_bytes(array)
            }

            fn encode(self, bytes: &mut [u8]) {
                bytes.copy_from_slice(&self.to_le_bytes());
            }
        }
    };
}

impl_guest_value!(u8, 1);
impl_guest_value!(u16, 2);
impl_guest_value!(u32, 4);
impl_guest_value!(u64, 8);

fn map_region(guest_address: u64, length: u64) -> Result<RamRegion> {
    // SAFETY: sysconf with _SC_PAGESIZE has no pointer arguments or side effects.
    let host_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = usize::try_from(host_page_size)
        .ok()
        .filter(|size| *size > 0)
        .ok_or_else(|| UhvmError::new("could not determine host page size"))?;
    let length = usize::try_from(length)
        .map_err(|_| UhvmError::new("guest RAM region is too large for this host"))?;
    let guard_length = page_size
        .checked_mul(2)
        .ok_or_else(|| UhvmError::new("guest RAM guard size overflows"))?;
    let mapping_length = length
        .checked_add(guard_length)
        .ok_or_else(|| UhvmError::new("guest RAM mapping size overflows"))?;
    // SAFETY: mmap is called with a null address, valid positive length and flags;
    // the returned mapping is checked before it is used.
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mapping_length,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    if mapping == libc::MAP_FAILED {
        return Err(UhvmError::new(format!(
            "map guest RAM: {}",
            io::Error::last_os_error()
        )));
    }
    let Some(mapping) = NonNull::new(mapping.cast::<u8>()) else {
        // SAFETY: mapping is the successful mmap result and mapping_length is exact.
        unsafe {
            libc::munmap(mapping.cast(), mapping_length);
        }
        return Err(UhvmError::new("mmap returned a null address"));
    };
    // SAFETY: the address and length describe the interior of the successful mmap.
    let result = unsafe {
        libc::mprotect(
            mapping.as_ptr().add(page_size).cast(),
            length,
            libc::PROT_READ | libc::PROT_WRITE,
        )
    };
    if result != 0 {
        // SAFETY: mapping is the successful mmap result and mapping_length is exact.
        unsafe {
            libc::munmap(mapping.as_ptr().cast(), mapping_length);
        }
        return Err(UhvmError::new(format!(
            "protect guest RAM: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(RamRegion {
        guest_address,
        length,
        mapping,
        mapping_length,
        page_size,
    })
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::GuestMemory;

    #[test]
    fn guest_memory_rejects_out_of_range_accesses() -> Result<(), Box<dyn Error>> {
        let memory = GuestMemory::new(1)?;
        let mut bytes = [0; 2];
        assert!(memory.read_at(1024 * 1024 - 1, &mut bytes).is_err());
        assert!(memory.write_obj(1024 * 1024, 1_u8).is_err());
        assert!(memory.read_obj::<u8>(u64::MAX).is_err());
        Ok(())
    }

    #[test]
    fn guest_memory_maps_high_ram_after_mmio_hole() -> Result<(), Box<dyn Error>> {
        let memory = GuestMemory::new(4096)?;
        let regions = memory.regions().collect::<Vec<_>>();
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].guest_address(), 0);
        assert_eq!(regions[0].len(), 3 * 1024 * 1024 * 1024);
        assert_eq!(regions[1].guest_address(), 4 * 1024 * 1024 * 1024);
        assert!(!memory.contains_range(3 * 1024 * 1024 * 1024, 1));
        Ok(())
    }
}
