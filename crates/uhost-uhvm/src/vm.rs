use std::{
    fs::OpenOptions,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
};

use kvm_bindings::{
    KVM_MP_STATE_UNINITIALIZED, KVM_PIT_SPEAKER_DUMMY, kvm_mp_state, kvm_pit_config,
};
use kvm_ioctls::{IoEventAddress, Kvm};
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
    serial: Mutex<SerialPort>,
    drives: Vec<Arc<Mutex<VirtioBlock>>>,
}

impl Bus {
    pub(super) fn io_read(&self, port: u16, data: &mut [u8]) -> Result<Option<VmmExit>> {
        data.fill(0);
        if (0x3f8..=0x3ff).contains(&port) && !data.is_empty() {
            data[0] = self
                .serial
                .lock()
                .map_err(|_| UhvmError::new("serial device lock is poisoned"))?
                .read(port);
        }
        Ok(None)
    }

    pub(super) fn io_write(&self, port: u16, data: &[u8]) -> Result<Option<VmmExit>> {
        if data.is_empty() {
            return Ok(None);
        }
        if (0x3f8..=0x3ff).contains(&port) {
            self.serial
                .lock()
                .map_err(|_| UhvmError::new("serial device lock is poisoned"))?
                .write(port, data[0])?;
        } else if port == 0x64 && data[0] == 0xfe {
            return Ok(Some(VmmExit::GuestReset));
        }
        Ok(None)
    }

    pub(super) fn mmio_read(&self, address: u64, data: &mut [u8]) -> Result<Option<VmmExit>> {
        data.fill(0);
        if let Some((device, offset)) = self.drive_at(address)
            && !data.is_empty()
        {
            let value = self.drives[device]
                .lock()
                .map_err(|_| UhvmError::new("virtio block device lock is poisoned"))?
                .read_register(offset);
            let bytes = value.to_le_bytes();
            let length = data.len().min(bytes.len());
            data[..length].copy_from_slice(&bytes[..length]);
        }
        Ok(None)
    }

    pub(super) fn mmio_write(&self, address: u64, data: &[u8]) -> Result<Option<VmmExit>> {
        if let Some((device, offset)) = self.drive_at(address) {
            let mut bytes = [0_u8; 4];
            let length = data.len().min(bytes.len());
            bytes[..length].copy_from_slice(&data[..length]);
            let value = u32::from_le_bytes(bytes);
            self.drives[device]
                .lock()
                .map_err(|_| UhvmError::new("virtio block device lock is poisoned"))?
                .write_register(offset, value, &self.memory)?;
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
    let (serial_output_sender, serial_output_thread) =
        crate::devices::serial::spawn_output_writer(serial_output, config.seccomp)
            .map_err(|error| UhvmError::new(format!("spawn serial output thread: {error}")))?;
    let (serial, serial_input) = SerialPort::new(serial_output_sender, serial_irq)?;
    let input_thread = crate::devices::serial::spawn_stdin_reader(serial_input, config.seccomp)
        .map_err(|error| UhvmError::new(format!("spawn serial input thread: {error}")))?;

    let mut drives = Vec::with_capacity(config.drives.len());
    let mut drive_workers = Vec::with_capacity(config.drives.len());
    for (index, drive) in drive_configs.iter().enumerate() {
        let irq = EventFd::new(0)
            .map_err(|error| UhvmError::new(format!("create virtio irq eventfd: {error}")))?;
        vm.register_irqfd(&irq, VIRTIO_IRQ_BASE + index as u32)
            .map_err(|error| UhvmError::new(format!("register virtio irqfd: {error}")))?;
        let notification = EventFd::new(0).map_err(|error| {
            UhvmError::new(format!("create virtio notification eventfd: {error}"))
        })?;
        let address = MMIO_BASE + index as u64 * MMIO_STRIDE + 0x50;
        vm.register_ioevent(&notification, &IoEventAddress::Mmio(address), 0_u32)
            .map_err(|error| UhvmError::new(format!("register virtio ioeventfd: {error}")))?;
        let device_notification = notification.try_clone().map_err(|error| {
            UhvmError::new(format!("clone virtio notification eventfd: {error}"))
        })?;
        let worker_notification = notification.try_clone().map_err(|error| {
            UhvmError::new(format!("clone virtio notification eventfd: {error}"))
        })?;
        let device = Arc::new(Mutex::new(VirtioBlock::open(
            &drive.path,
            drive.read_only,
            irq,
            device_notification,
        )?));
        let stop = Arc::new(AtomicBool::new(false));
        let worker = spawn_drive_worker(
            index,
            worker_notification,
            Arc::clone(&device),
            Arc::clone(&memory),
            Arc::clone(&stop),
            config.seccomp,
        )?;
        drive_workers.push(DriveWorker {
            stop,
            notification,
            thread: worker,
        });
        drives.push(device);
    }
    let bus = Arc::new(Bus {
        memory: Arc::clone(&memory),
        serial: Mutex::new(serial),
        drives,
    });

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
    if let Err(error) = seccomp::apply_vmm_filter(config.seccomp) {
        stop_drive_workers(drive_workers)?;
        return Err(error);
    }
    let exit = receiver.recv();
    stop_drive_workers(drive_workers)?;
    let exit = exit.map_err(|error| UhvmError::new(format!("wait for vCPU exit: {error}")))?;
    bus.serial
        .lock()
        .map_err(|_| UhvmError::new("serial device lock is poisoned"))?
        .close_output();
    serial_output_thread
        .join()
        .map_err(|_| UhvmError::new("serial output thread panicked"))??;
    drop(threads);
    drop(input_thread);
    drop(bus);
    drop(vm);
    Ok(exit)
}

struct DriveWorker {
    stop: Arc<AtomicBool>,
    notification: EventFd,
    thread: JoinHandle<Result<()>>,
}

fn spawn_drive_worker(
    index: usize,
    notification: EventFd,
    drive: Arc<Mutex<VirtioBlock>>,
    memory: Arc<GuestMemory>,
    stop: Arc<AtomicBool>,
    seccomp_level: crate::SeccompLevel,
) -> Result<JoinHandle<Result<()>>> {
    thread::Builder::new()
        .name(format!("uhvm-blk{index}"))
        .spawn(move || {
            seccomp::apply_device_filter(seccomp_level)?;
            loop {
                match notification.read() {
                    Ok(_) if stop.load(Ordering::Acquire) => break,
                    Ok(_) => {
                        drive
                            .lock()
                            .map_err(|_| UhvmError::new("virtio block device lock is poisoned"))?
                            .process_queue(&memory);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        return Err(UhvmError::new(format!(
                            "read virtio notification eventfd: {error}"
                        )));
                    }
                }
            }
            Ok(())
        })
        .map_err(|error| UhvmError::new(format!("spawn virtio worker {index}: {error}")))
}

fn stop_drive_workers(workers: Vec<DriveWorker>) -> Result<()> {
    for worker in &workers {
        worker.stop.store(true, Ordering::Release);
        let _ = worker.notification.write(1);
    }
    for worker in workers {
        worker
            .thread
            .join()
            .map_err(|_| UhvmError::new("virtio worker thread panicked"))??;
    }
    Ok(())
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
