//! Minimal Linux/KVM virtual machine runtime.

#![deny(clippy::undocumented_unsafe_blocks)]

use std::{error::Error, fmt, path::PathBuf};

/// Result type used by uHVM.
pub type Result<T> = std::result::Result<T, UhvmError>;

/// Error returned by the uHVM runtime.
#[derive(Debug)]
pub struct UhvmError {
    message: String,
}

impl UhvmError {
    /// Creates an error with a descriptive message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for UhvmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for UhvmError {}

/// Explicit process-hardening operations for the uHVM command-line application.
pub mod process;

/// Guest drive configuration.
#[derive(Debug, Clone)]
pub struct DriveConfig {
    /// Raw block image path.
    pub path: PathBuf,
    /// Whether writes to this drive are rejected.
    pub read_only: bool,
    /// Whether this is the guest root drive.
    pub is_root: bool,
}

/// Destination for guest serial output.
#[derive(Debug, Clone)]
pub enum SerialSink {
    /// Write guest serial bytes to stdout.
    Stdout,
    /// Write guest serial bytes to this file.
    File(PathBuf),
}

/// Seccomp policy applied to uHVM threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompLevel {
    /// Do not install seccomp filters.
    Off,
    /// Log denied syscalls while permitting them.
    Log,
    /// Terminate the process when a syscall is not permitted.
    Kill,
}

/// VM startup configuration.
#[derive(Debug, Clone)]
pub struct UhvmConfig {
    /// Linux ELF kernel image.
    pub kernel: PathBuf,
    /// Kernel command line.
    pub cmdline: String,
    /// Guest memory size in MiB.
    pub mem_mib: u64,
    /// Number of virtual CPUs.
    pub vcpus: u8,
    /// Guest block drives.
    pub drives: Vec<DriveConfig>,
    /// Guest serial output destination.
    pub serial: SerialSink,
    /// Per-thread seccomp level.
    pub seccomp: SeccompLevel,
}

/// Reason the guest stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmmExit {
    /// Guest requested a reset.
    GuestReset,
    /// Guest shut down.
    GuestShutdown,
    /// Guest or host runtime failed.
    Error(String),
}

/// VM facade.
pub struct Vmm;

impl Vmm {
    /// Creates and runs a guest until it exits.
    pub fn boot(config: UhvmConfig) -> Result<VmmExit> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            vm::boot(config)
        }
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = config;
            Err(UhvmError::new(
                "unsupported platform: uHVM requires Linux x86_64",
            ))
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
/// Linux host syscall and guest-memory integration.
pub mod sys;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod acpi;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod boot;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod cpuid;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod devices;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod seccomp;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod vcpu;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod vm;
