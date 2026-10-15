//! Explicit process-hardening helpers for applications embedding uHVM.

use crate::Result;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
use crate::UhvmError;

/// Closes inherited file descriptors other than standard input, output, and error.
///
/// Call this only when the owning application intends to close its inherited
/// descriptors; [`crate::Vmm::boot`] deliberately leaves process descriptors alone.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn close_inherited_fds() -> Result<()> {
    crate::sys::close_inherited_fds()
}

/// Closes inherited file descriptors on unsupported platforms.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn close_inherited_fds() -> Result<()> {
    Err(UhvmError::new(
        "unsupported platform: process hardening requires Linux x86_64",
    ))
}

/// Applies the uHVM process-level hardening settings.
///
/// Call this from the owning executable before [`crate::Vmm::boot`] when the
/// application is willing to apply these process-wide restrictions.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn harden_process() -> Result<()> {
    crate::sys::harden_process()
}

/// Reports unsupported process hardening on non-Linux x86_64 platforms.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn harden_process() -> Result<()> {
    Err(UhvmError::new(
        "unsupported platform: process hardening requires Linux x86_64",
    ))
}
