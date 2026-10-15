use std::sync::Arc;

use kvm_bindings::{KVM_SYSTEM_EVENT_RESET, KVM_SYSTEM_EVENT_SHUTDOWN};
use kvm_ioctls::{VcpuExit, VcpuFd};

use crate::{Result, SeccompLevel, VmmExit, seccomp, vm::Bus};

pub(super) fn run(mut vcpu: VcpuFd, bus: Arc<Bus>, seccomp_level: SeccompLevel) -> VmmExit {
    if let Err(error) = seccomp::apply_vcpu_filter(seccomp_level) {
        return VmmExit::Error(error.to_string());
    }
    loop {
        let exit = match vcpu.run() {
            Ok(exit) => exit,
            Err(error) if error.errno() == libc::EINTR || error.errno() == libc::EAGAIN => {
                continue;
            }
            Err(error) => return VmmExit::Error(format!("KVM_RUN failed: {error}")),
        };
        let handled = match exit {
            VcpuExit::IoIn(port, data) => dispatch(&bus, |bus| bus.io_read(port, data)),
            VcpuExit::IoOut(port, data) => dispatch(&bus, |bus| bus.io_write(port, data)),
            VcpuExit::MmioRead(address, data) => dispatch(&bus, |bus| bus.mmio_read(address, data)),
            VcpuExit::MmioWrite(address, data) => {
                dispatch(&bus, |bus| bus.mmio_write(address, data))
            }
            VcpuExit::Hlt | VcpuExit::Intr | VcpuExit::IrqWindowOpen => Ok(None),
            VcpuExit::Shutdown => return VmmExit::GuestShutdown,
            VcpuExit::SystemEvent(event_type, _) if event_type == KVM_SYSTEM_EVENT_RESET => {
                return VmmExit::GuestReset;
            }
            VcpuExit::SystemEvent(event_type, _) if event_type == KVM_SYSTEM_EVENT_SHUTDOWN => {
                return VmmExit::GuestShutdown;
            }
            VcpuExit::SystemEvent(event_type, _) => {
                return VmmExit::Error(format!("unsupported KVM system event {event_type}"));
            }
            VcpuExit::FailEntry(reason, cpu) => {
                return VmmExit::Error(format!(
                    "KVM fail-entry on CPU {cpu}, hardware reason {reason:#x}"
                ));
            }
            VcpuExit::InternalError => {
                return VmmExit::Error(String::from("KVM reported an internal vCPU error"));
            }
            other => return VmmExit::Error(format!("unsupported KVM vCPU exit: {other:?}")),
        };
        match handled {
            Ok(Some(exit)) => return exit,
            Ok(None) => {}
            Err(error) => return VmmExit::Error(error.to_string()),
        }
    }
}

fn dispatch(
    bus: &Bus,
    operation: impl FnOnce(&Bus) -> Result<Option<VmmExit>>,
) -> Result<Option<VmmExit>> {
    operation(bus)
}
