//! Linux host syscalls and KVM memory registration.

#![allow(unsafe_code)]

/// Guarded guest RAM and checked GPA accesses.
pub mod memory;

use std::{fs, os::fd::RawFd};

use kvm_ioctls::VmFd;

use crate::Result;

/// Registers each guest RAM region with KVM.
pub fn register_guest_memory(vm: &VmFd, memory: &memory::GuestMemory) -> Result<()> {
    for (slot, region) in memory.regions().enumerate() {
        let descriptor = kvm_bindings::kvm_userspace_memory_region {
            slot: slot as u32,
            flags: 0,
            guest_phys_addr: region.guest_address(),
            memory_size: region.len(),
            userspace_addr: region.host_address(),
        };
        // SAFETY: GuestMemory owns a stable, page-aligned mapping for the full region
        // until after the VM is destroyed; slots are unique and match the region bounds.
        unsafe { vm.set_user_memory_region(descriptor) }
            .map_err(|error| crate::UhvmError::new(format!("register KVM memory: {error}")))?;
    }
    Ok(())
}

/// Closes inherited descriptors above stderr before opening VM-owned resources.
pub fn close_inherited_fds() -> Result<()> {
    let descriptors = fs::read_dir("/proc/self/fd")
        .map_err(|error| crate::UhvmError::new(format!("list inherited descriptors: {error}")))?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<RawFd>().ok())
        .filter(|descriptor| *descriptor > 2)
        .collect::<Vec<_>>();
    for descriptor in descriptors {
        // SAFETY: these descriptors were enumerated from this process and are
        // intentionally closed before any VM-owned descriptor is opened.
        unsafe {
            libc::close(descriptor);
        }
    }
    Ok(())
}

/// Applies process-level hardening before guest execution.
pub fn harden_process() -> Result<()> {
    // SAFETY: PR_SET_NO_NEW_PRIVS takes an integer flag and ignores the remaining arguments.
    let no_new_privs = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if no_new_privs != 0 {
        return Err(crate::UhvmError::new(format!(
            "set no_new_privs: {}",
            std::io::Error::last_os_error()
        )));
    }
    set_soft_limit(libc::RLIMIT_NOFILE, 1024)?;
    set_soft_limit(libc::RLIMIT_NPROC, 1024)?;
    Ok(())
}

fn set_soft_limit(resource: libc::__rlimit_resource_t, limit: libc::rlim_t) -> Result<()> {
    // SAFETY: rlimit contains only integer fields, for which zero is a valid value.
    let mut current = unsafe { std::mem::zeroed::<libc::rlimit>() };
    // SAFETY: current points to a correctly initialized rlimit-sized output buffer.
    if unsafe { libc::getrlimit(resource, &mut current) } != 0 {
        return Err(crate::UhvmError::new(format!(
            "read process resource limit: {}",
            std::io::Error::last_os_error()
        )));
    }
    current.rlim_cur = current.rlim_max.min(limit);
    // SAFETY: current contains the current hard limit and a reduced soft limit.
    if unsafe { libc::setrlimit(resource, &current) } != 0 {
        return Err(crate::UhvmError::new(format!(
            "set process resource limit: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}
