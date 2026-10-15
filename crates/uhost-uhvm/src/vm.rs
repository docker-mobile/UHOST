use std::{
    fs::OpenOptions,
    io,
    sync::{Arc, Mutex, mpsc},
    thread,
};

use kvm_bindings::{
    KVM_MP_STATE_UNINITIALIZED, KVM_PIT_SPEAKER_DUMMY, kvm_mp_state, kvm_pit_config,
};
use kvm_ioctls::Kvm;
use vmm_sys_util::eventfd::EventFd;

use crate::{
    Result, SerialSink, UhvmConfig, UhvmError, VmmExit, acpi, boot, cpuid,
    devices::{SerialPort, VirtioBlock},
    seccomp,
    sys::{self, memory::GuestMemory},
    vcpu,
};

const MMIO_BASE: u64 = 0xd000_0000;
const MMIO_STRIDE: u64 = 0x1000;
const SERIAL_IRQ: u32 = 4;
const VIRTIO_IRQ_BASE: u32 = 5;

pub(super) struct Bus {
    memory: Arc<GuestMemory>,
    serial: SerialPort,
    drives: Vec<VirtioBlock>,
}

impl Bus {
    pub(super) fn io_read(&mut self, port: u16, data: &mut [u8]) -> Result<Option<VmmExit>> {
        data.fill(0);
        if (0x3f8..=0x3ff).contains(&port) && !data.is_empty() {
            data[0] = self.serial.read(port);
        }
        Ok(None)
    }

    pub(super) fn io_write(&mut self, port: u16, data: &[u8]) -> Result<Option<VmmExit>> {
        if data.is_empty() {
            return Ok(None);
        }
        if (0x3f8..=0x3ff).contains(&port) {
            self.serial.write(port, data[0])?;
        } else if port == 0x64 && data[0] == 0xfe {
            return Ok(Some(VmmExit::GuestReset));
        }
        Ok(None)
    }

    pub(super) fn mmio_read(&mut self, address: u64, data: &mut [u8]) -> Result<Option<VmmExit>> {
        data.fill(0);
        if let Some((device, offset)) = self.drive_at(address)
            && !data.is_empty()
        {
            let value = self.drives[device].read_register(offset);
            let bytes = value.to_le_bytes();
            let length = data.len().min(bytes.len());
            data[..length].copy_from_slice(&bytes[..length]);
        }
        Ok(None)
    }

    pub(super) fn mmio_write(&mut self, address: u64, data: &[u8]) -> Result<Option<VmmExit>> {
        if let Some((device, offset)) = self.drive_at(address) {
            let mut bytes = [0_u8; 4];
            let length = data.len().min(bytes.len());
            bytes[..length].copy_from_slice(&data[..length]);
            let value = u32::from_le_bytes(bytes);
            self.drives[device].write_register(offset, value, &self.memory)?;
        }
        Ok(None)
    }

    fn drive_at(&self, address: u64) -> Option<(usize, u64)> {
        let offset = address.checked_sub(MMIO_BASE)?;
        let index = usize::try_from(offset / MMIO_STRIDE).ok()?;
        self.drives
            .get(index)
            .map(|_| (index, offset % MMIO_STRIDE))
    }
}

pub(super) fn boot(config: UhvmConfig) -> Result<VmmExit> {
    if config.vcpus == 0 || config.vcpus > 8 {
        return Err(UhvmError::new("vcpus must be between 1 and 8"));
    }
    if config.mem_mib < 16 {
        return Err(UhvmError::new("guest memory must be at least 16 MiB"));
    }
    if config.drives.is_empty() {
        return Err(UhvmError::new(
            "at least one virtio block drive is required",
        ));
    }
    if config.drives.iter().filter(|drive| drive.is_root).count() != 1 {
        return Err(UhvmError::new(
            "exactly one virtio block drive must be marked as root",
        ));
    }
    if config.drives.len() > 11 {
        return Err(UhvmError::new(
            "uHVM supports at most 11 virtio block drives",
        ));
    }
    let mut drive_configs = config.drives.clone();
    drive_configs.sort_by_key(|drive| !drive.is_root);
    sys::close_inherited_fds()?;
    sys::harden_process()?;
    let kvm = Kvm::new().map_err(|error| UhvmError::new(format!("open /dev/kvm: {error}")))?;
    let vm = kvm
        .create_vm()
        .map_err(|error| UhvmError::new(format!("create KVM VM: {error}")))?;
    vm.set_tss_address(0xfffbd000)
        .map_err(|error| UhvmError::new(format!("set KVM TSS address: {error}")))?;
    vm.create_irq_chip()
        .map_err(|error| UhvmError::new(format!("create KVM irqchip: {error}")))?;
    vm.create_pit2(kvm_pit_config {
        flags: KVM_PIT_SPEAKER_DUMMY,
        ..kvm_pit_config::default()
    })
    .map_err(|error| UhvmError::new(format!("create KVM PIT: {error}")))?;
    let memory = Arc::new(GuestMemory::new(config.mem_mib)?);
    sys::register_guest_memory(&vm, &memory)?;
    boot::write_mp_table(&memory, config.vcpus)?;
    acpi::write_tables(&memory, config.vcpus, drive_configs.len())?;

    let mut command_line = config.cmdline.clone();
    for (index, _) in drive_configs.iter().enumerate() {
        let address = MMIO_BASE + index as u64 * MMIO_STRIDE;
        let irq = VIRTIO_IRQ_BASE + index as u32;
        command_line.push_str(&format!(" virtio_mmio.device=4K@{address:#x}:{irq}"));
    }
    boot::prepare_boot(&memory, config.mem_mib, &command_line)?;
    let entry = boot::load_elf_kernel(&config.kernel, &memory)?;

    let serial_irq = EventFd::new(0)
        .map_err(|error| UhvmError::new(format!("create serial irq eventfd: {error}")))?;
    vm.register_irqfd(&serial_irq, SERIAL_IRQ)
        .map_err(|error| UhvmError::new(format!("register serial irqfd: {error}")))?;
    let serial_output = serial_output(&config.serial)?;
    let (serial, serial_input) = SerialPort::new(serial_output, serial_irq)?;
    let input_thread = crate::devices::serial::spawn_stdin_reader(serial_input, config.seccomp)
        .map_err(|error| UhvmError::new(format!("spawn serial input thread: {error}")))?;

    let mut drives = Vec::with_capacity(config.drives.len());
    for (index, drive) in drive_configs.iter().enumerate() {
        let irq = EventFd::new(0)
            .map_err(|error| UhvmError::new(format!("create virtio irq eventfd: {error}")))?;
        vm.register_irqfd(&irq, VIRTIO_IRQ_BASE + index as u32)
            .map_err(|error| UhvmError::new(format!("register virtio irqfd: {error}")))?;
        drives.push(VirtioBlock::open(&drive.path, drive.read_only, irq)?);
    }
    let bus = Arc::new(Mutex::new(Bus {
        memory: Arc::clone(&memory),
        serial,
        drives,
    }));

    let mut vcpus = Vec::with_capacity(usize::from(config.vcpus));
    for cpu_id in 0..config.vcpus {
        let vcpu = vm
            .create_vcpu(u64::from(cpu_id))
            .map_err(|error| UhvmError::new(format!("create vCPU {cpu_id}: {error}")))?;
        cpuid::configure_cpuid(&kvm, &vcpu, cpu_id, config.vcpus)?;
        if cpu_id == 0 {
            boot::configure_boot_vcpu(&vcpu, entry)?;
        } else {
            vcpu.set_mp_state(kvm_mp_state {
                mp_state: KVM_MP_STATE_UNINITIALIZED,
            })
            .map_err(|error| UhvmError::new(format!("initialize AP vCPU {cpu_id}: {error}")))?;
        }
        vcpus.push(vcpu);
    }

    let (sender, receiver) = mpsc::channel();
    let mut threads = Vec::with_capacity(vcpus.len());
    for vcpu in vcpus {
        let bus = Arc::clone(&bus);
        let sender = sender.clone();
        let level = config.seccomp;
        threads.push(
            thread::Builder::new()
                .name(String::from("uhvm-vcpu"))
                .spawn(move || {
                    let exit = vcpu::run(vcpu, bus, level);
                    let _ = sender.send(exit);
                })
                .map_err(|error| UhvmError::new(format!("spawn vCPU thread: {error}")))?,
        );
    }
    drop(sender);
    seccomp::apply_vmm_filter(config.seccomp)?;
    let exit = receiver
        .recv()
        .map_err(|error| UhvmError::new(format!("wait for vCPU exit: {error}")))?;
    drop(threads);
    drop(input_thread);
    drop(bus);
    drop(vm);
    Ok(exit)
}

fn serial_output(sink: &SerialSink) -> Result<Box<dyn io::Write + Send>> {
    match sink {
        SerialSink::Stdout => Ok(Box::new(io::stdout())),
        SerialSink::File(path) => {
            let file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)
                .map_err(|error| {
                    UhvmError::new(format!("open serial log {}: {error}", path.display()))
                })?;
            Ok(Box::new(file))
        }
    }
}
