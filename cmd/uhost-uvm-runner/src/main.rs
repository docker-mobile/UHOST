#![recursion_limit = "256"]

use std::{
    collections::BTreeSet,
    env, fs,
    io::{self, BufRead, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, TryRecvError},
    },
    thread,
    time::Duration,
};

use uhost_core::{PlatformError, Result, sha256_hex};
use uhost_uvm::{
    BootDevice, BootPath, DeviceModel, ExecutionClass, GuestArchitecture, HypervisorBackend,
    MachineFamily, MemoryBacking, SandboxLayer,
};
use uhost_uvm_machine::MachineSpec;
use uhost_uvm_softvm::{
    SoftVmArtifactPolicy, SoftVmBootWitness, SoftVmGuestCommandResult, SoftVmGuestControl,
    SoftVmHeartbeat, SoftVmInstance, SoftVmPhase, SoftVmRuntimeSpec,
};

const UVM_SANDBOX_LAYERS_ENV: &str = "UVM_SANDBOX_LAYERS";
const UVM_SOFTVM_WORKERS_ENV: &str = "UVM_SOFTVM_WORKERS";
const VIRTIO_NET_MMIO_REGION_NAME: &str = "virtio_net";
const RUNNER_SANDBOX_ENFORCEMENT_MODE: &str = "worker_contract";
const RUNNER_SANDBOX_CONTRACT_SOURCE: &str = "launch_contract";
const RUNNER_WORKER_MANIFEST_VERSION: &str = "v1";
const QEMU_TCG_GENERATED_VALIDATION_BUNDLE: &str = "runner_qemu_tcg_conformance";
const SOFTWARE_DBT_NETWORK_MODE: &str = "guest_owned_usernet_nat";
const SOFTWARE_DBT_EGRESS_TRANSPORT: &str = "guest_owned_tcp_udp_http_https_nat_v1";
const SOFTWARE_DBT_INGRESS_TRANSPORT: &str = "guest_owned_tcp_udp_http_nat_v1";
const SOFTWARE_DBT_DEFAULT_INGRESS_HTTP_BIND: &str = "127.0.0.1:0";
const SOFTWARE_DBT_DEFAULT_INGRESS_TCP_BIND: &str = "127.0.0.1:0";
const SOFTWARE_DBT_DEFAULT_INGRESS_UDP_BIND: &str = "127.0.0.1:0";
const SOFTWARE_DBT_GUEST_WEB_ROOT: &str = "/var/www";
const MAX_HTTP_INGRESS_REQUEST_BYTES: usize = 16 * 1024;
const MAX_TCP_INGRESS_READ_BYTES: usize = 64 * 1024;
const MAX_UDP_INGRESS_READ_BYTES: usize = 64 * 1024;
const DEFAULT_TCP_INGRESS_SERVICE_NAME: &str = "default";
const DEFAULT_UDP_INGRESS_SERVICE_NAME: &str = "default";
static MANAGED_INGRESS_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);
const SOFTWARE_DBT_SANDBOX_LAYER_ORDER: [SandboxLayer; 4] = [
    SandboxLayer::CapabilityDrop,
    SandboxLayer::CgroupV2,
    SandboxLayer::Namespaces,
    SandboxLayer::Seccomp,
];
const SOFTWARE_DBT_WORKER_ORDER: [RunnerWorkerRole; 4] = [
    RunnerWorkerRole::Supervisor,
    RunnerWorkerRole::Core,
    RunnerWorkerRole::Block,
    RunnerWorkerRole::Net,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunnerMode {
    OneShot,
    Supervise,
}

impl RunnerMode {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "one_shot" | "oneshot" => Ok(Self::OneShot),
            "supervise" | "supervised" => Ok(Self::Supervise),
            _ => Err(PlatformError::invalid(
                "runner_mode must be one of `one_shot` or `supervise`",
            )),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::OneShot => "one_shot",
            Self::Supervise => "supervise",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunnerWorkerRole {
    Supervisor,
    Core,
    Block,
    Net,
}

impl RunnerWorkerRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Supervisor => "supervisor",
            Self::Core => "core",
            Self::Block => "block",
            Self::Net => "net",
        }
    }

    const fn seccomp_profile(self) -> &'static str {
        match self {
            Self::Supervisor => "supervisor_control_v1",
            Self::Core => "guest_core_v1",
            Self::Block => "block_io_v1",
            Self::Net => "net_io_v1",
        }
    }

    const fn process_binding(self) -> &'static str {
        match self {
            Self::Supervisor => "runner_process",
            Self::Core | Self::Block | Self::Net => "shared_runner_process",
        }
    }

    const fn state_for_phase(self, phase: SoftVmPhase) -> &'static str {
        match phase {
            SoftVmPhase::Created => "registered",
            SoftVmPhase::Prepared => "prepared",
            SoftVmPhase::Running => "running",
            SoftVmPhase::Stopped => "stopped",
        }
    }

    const fn execution_scope(self) -> &'static str {
        match self {
            Self::Supervisor => "lifecycle_orchestration",
            Self::Core => "softvm_core",
            Self::Block => "artifact_staging",
            Self::Net => "virtio_net_observation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunnerExecutionContract {
    sandbox_layers: Vec<String>,
    workers: Vec<RunnerWorkerRole>,
}

impl RunnerExecutionContract {
    fn from_process_env() -> Result<Self> {
        let sandbox_layers = env::var(UVM_SANDBOX_LAYERS_ENV).ok();
        let workers = env::var(UVM_SOFTVM_WORKERS_ENV).ok();
        Self::from_values(sandbox_layers.as_deref(), workers.as_deref())
    }

    fn from_values(sandbox_layers: Option<&str>, workers: Option<&str>) -> Result<Self> {
        let expected_sandbox_layers = SOFTWARE_DBT_SANDBOX_LAYER_ORDER
            .iter()
            .map(|layer| layer.as_str())
            .collect::<Vec<_>>();
        let expected_workers = SOFTWARE_DBT_WORKER_ORDER
            .iter()
            .map(|worker| worker.as_str())
            .collect::<Vec<_>>();

        if let Some(sandbox_layers) = sandbox_layers {
            let actual = parse_contract_csv(sandbox_layers, UVM_SANDBOX_LAYERS_ENV)?;
            validate_exact_contract_list(
                &actual,
                &expected_sandbox_layers,
                UVM_SANDBOX_LAYERS_ENV,
            )?;
        }
        if let Some(workers) = workers {
            let actual = parse_contract_csv(workers, UVM_SOFTVM_WORKERS_ENV)?;
            validate_exact_contract_list(&actual, &expected_workers, UVM_SOFTVM_WORKERS_ENV)?;
        }

        Ok(Self {
            sandbox_layers: expected_sandbox_layers
                .into_iter()
                .map(String::from)
                .collect(),
            workers: SOFTWARE_DBT_WORKER_ORDER.to_vec(),
        })
    }

    fn worker_states(&self, phase: SoftVmPhase) -> Vec<String> {
        self.workers
            .iter()
            .map(|worker| format!("{}:{}", worker.as_str(), worker.state_for_phase(phase)))
            .collect()
    }

    fn enforce_worker(&self, role: RunnerWorkerRole) -> Result<RunnerWorkerSandboxContract> {
        if !self.workers.contains(&role) {
            return Err(PlatformError::conflict(format!(
                "runner worker contract is missing `{}`",
                role.as_str()
            )));
        }
        let expected_layers = SOFTWARE_DBT_SANDBOX_LAYER_ORDER
            .iter()
            .map(|layer| String::from(layer.as_str()))
            .collect::<Vec<_>>();
        if self.sandbox_layers != expected_layers {
            return Err(PlatformError::conflict(format!(
                "worker `{}` requires sandbox layer order `{}`",
                role.as_str(),
                expected_layers.join(",")
            ))
            .with_detail(format!("got `{}`", self.sandbox_layers.join(","))));
        }
        Ok(RunnerWorkerSandboxContract {
            role,
            sandbox_layers: self.sandbox_layers.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunnerWorkerSandboxContract {
    role: RunnerWorkerRole,
    sandbox_layers: Vec<String>,
}

impl RunnerWorkerSandboxContract {
    fn sandbox_layers(&self) -> &[String] {
        &self.sandbox_layers
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalizedExecutionArtifacts {
    disk_image: String,
    cdrom_image: Option<String>,
}

#[derive(Debug)]
struct StartedRuntime {
    instance: SoftVmInstance,
    boot_witness: SoftVmBootWitness,
    guest_command_results: Vec<SoftVmGuestCommandResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockWorkerObservation {
    artifact_count: usize,
    disk_image: String,
    cdrom_image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetWorkerObservation {
    virtio_net_mmio_present: bool,
    guest_control_ready: bool,
    host_relay_egress_ready: bool,
    network_mode: String,
    internet_nat: bool,
    ssh_available: bool,
    guest_exec_route_available: bool,
    egress_transport: String,
    ingress_transport: String,
    ingress_http_ready: bool,
    ingress_tcp_ready: bool,
    ingress_udp_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunnerWorkerObservationSnapshot {
    block: BlockWorkerObservation,
    net: NetWorkerObservation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedIngressState {
    http_bind: String,
    http_url: String,
    web_root: PathBuf,
    ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedTcpIngressState {
    tcp_bind: String,
    service_name: String,
    ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ManagedTcpIngressMode {
    Echo,
    StaticResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedTcpIngressServiceConfig {
    name: String,
    bind: String,
    mode: ManagedTcpIngressMode,
    banner: Vec<u8>,
    response: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedUdpIngressState {
    udp_bind: String,
    service_name: String,
    ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ManagedUdpIngressMode {
    Echo,
    StaticResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedUdpIngressServiceConfig {
    name: String,
    bind: String,
    mode: ManagedUdpIngressMode,
    response: Vec<u8>,
}

#[derive(Debug)]
struct ManagedHttpIngress {
    state: ManagedIngressState,
    stop_flag: Arc<AtomicBool>,
    join_handle: Option<thread::JoinHandle<Result<()>>>,
}

#[derive(Debug)]
struct ManagedTcpIngress {
    state: ManagedTcpIngressState,
    requested_bind: String,
    service: Arc<Mutex<ManagedTcpIngressServiceConfig>>,
    stop_flag: Arc<AtomicBool>,
    join_handle: Option<thread::JoinHandle<Result<()>>>,
}

#[derive(Debug)]
struct ManagedUdpIngress {
    state: ManagedUdpIngressState,
    requested_bind: String,
    service: Arc<Mutex<ManagedUdpIngressServiceConfig>>,
    stop_flag: Arc<AtomicBool>,
    join_handle: Option<thread::JoinHandle<Result<()>>>,
}

#[derive(Debug, Clone, PartialEq)]
struct RunnerWorkerManifestState {
    workers: Vec<serde_json::Value>,
    guest_control_ready: bool,
    manifest_version: &'static str,
    manifest_fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupervisedCoreWorkerCommand {
    Heartbeat,
    Stop,
}

#[derive(Debug, Clone, PartialEq)]
struct SupervisedCoreWorkerStarted {
    phase: SoftVmPhase,
    configured_guest_memory_bytes: u64,
    boot_witness: SoftVmBootWitness,
    guest_command_results: Vec<SoftVmGuestCommandResult>,
    guest_control: SoftVmGuestControl,
    worker_manifest: RunnerWorkerManifestState,
}

#[derive(Debug, Clone, PartialEq)]
struct SupervisedCoreWorkerHeartbeat {
    phase: SoftVmPhase,
    heartbeat: SoftVmHeartbeat,
    guest_control: SoftVmGuestControl,
    worker_manifest: RunnerWorkerManifestState,
}

#[derive(Debug, Clone, PartialEq)]
struct SupervisedCoreWorkerStopped {
    phase: SoftVmPhase,
    final_heartbeat_sequence: u64,
    configured_guest_memory_bytes: u64,
    boot_witness: SoftVmBootWitness,
    guest_control: SoftVmGuestControl,
    worker_manifest: RunnerWorkerManifestState,
}

#[derive(Debug, Clone, PartialEq)]
enum SupervisedCoreWorkerUpdate {
    Started(SupervisedCoreWorkerStarted),
    Heartbeat(SupervisedCoreWorkerHeartbeat),
    Stopped(SupervisedCoreWorkerStopped),
}

#[derive(Debug)]
struct SupervisedCoreWorkerHandle {
    command_tx: mpsc::Sender<SupervisedCoreWorkerCommand>,
    update_rx: mpsc::Receiver<Result<SupervisedCoreWorkerUpdate>>,
    join_handle: Option<thread::JoinHandle<Result<()>>>,
}

impl SupervisedCoreWorkerHandle {
    fn receive_started(&self) -> Result<SupervisedCoreWorkerStarted> {
        match self.receive_update("failed to receive supervised core worker start state")? {
            SupervisedCoreWorkerUpdate::Started(started) => Ok(started),
            SupervisedCoreWorkerUpdate::Heartbeat(_) | SupervisedCoreWorkerUpdate::Stopped(_) => {
                Err(PlatformError::conflict(
                    "supervised core worker returned an unexpected update before start",
                ))
            }
        }
    }

    fn heartbeat(&self) -> Result<SupervisedCoreWorkerHeartbeat> {
        self.command_tx
            .send(SupervisedCoreWorkerCommand::Heartbeat)
            .map_err(|_| {
                PlatformError::unavailable("failed to send heartbeat command to core worker")
            })?;
        match self.receive_update("failed to receive supervised core worker heartbeat")? {
            SupervisedCoreWorkerUpdate::Heartbeat(heartbeat) => Ok(heartbeat),
            SupervisedCoreWorkerUpdate::Started(_) | SupervisedCoreWorkerUpdate::Stopped(_) => {
                Err(PlatformError::conflict(
                    "supervised core worker returned an unexpected non-heartbeat update",
                ))
            }
        }
    }

    fn stop(mut self) -> Result<SupervisedCoreWorkerStopped> {
        self.command_tx
            .send(SupervisedCoreWorkerCommand::Stop)
            .map_err(|_| {
                PlatformError::unavailable("failed to send stop command to core worker")
            })?;
        let stopped = match self
            .receive_update("failed to receive supervised core worker stop state")?
        {
            SupervisedCoreWorkerUpdate::Stopped(stopped) => stopped,
            SupervisedCoreWorkerUpdate::Started(_) | SupervisedCoreWorkerUpdate::Heartbeat(_) => {
                return Err(PlatformError::conflict(
                    "supervised core worker returned an unexpected non-stop update",
                ));
            }
        };
        self.join()?;
        Ok(stopped)
    }

    fn receive_update(&self, context: &'static str) -> Result<SupervisedCoreWorkerUpdate> {
        match self
            .update_rx
            .recv()
            .map_err(|_| PlatformError::unavailable(context))?
        {
            Ok(update) => Ok(update),
            Err(error) => Err(error),
        }
    }

    fn join(&mut self) -> Result<()> {
        let Some(join_handle) = self.join_handle.take() else {
            return Ok(());
        };
        match join_handle.join() {
            Ok(result) => result,
            Err(_) => Err(PlatformError::unavailable(
                "supervised core worker thread panicked",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunnerConfig {
    session_id: String,
    instance_id: String,
    runner_mode: RunnerMode,
    heartbeat_interval_ms: u64,
    max_heartbeats: Option<u64>,
    stop_sentinel: Option<String>,
    ingress_http_bind: Option<String>,
    ingress_tcp_bind: Option<String>,
    ingress_udp_bind: Option<String>,
    guest_architecture: GuestArchitecture,
    vcpu: u16,
    memory_mb: u64,
    memory_backing: MemoryBacking,
    firmware_profile: String,
    firmware_artifact: Option<String>,
    disk_image: String,
    cdrom_image: Option<String>,
    boot_device: BootDevice,
    boot_path: BootPath,
    device_model: DeviceModel,
    machine_family: MachineFamily,
    execution_class: ExecutionClass,
    restart_policy: String,
    migration_kind: String,
    probe_mode: Option<String>,
    guest_commands: Vec<String>,
    require_secure_boot: bool,
    telemetry: Vec<String>,
    numa_nodes: Vec<u8>,
}

impl RunnerConfig {
    fn parse(args: &[String]) -> Result<Self> {
        let mut session_id = None;
        let mut instance_id = None;
        let mut runner_mode = None;
        let mut heartbeat_interval_ms = None;
        let mut max_heartbeats = None;
        let mut stop_sentinel = None;
        let mut ingress_http_bind = None;
        let mut ingress_tcp_bind = None;
        let mut ingress_udp_bind = None;
        let mut guest_architecture = None;
        let mut vcpu = None;
        let mut memory_mb = None;
        let mut memory_backing = None;
        let mut firmware_profile = None;
        let mut firmware_artifact = None;
        let mut disk_image = None;
        let mut cdrom_image = None;
        let mut boot_device = None;
        let mut boot_path = None;
        let mut device_model = None;
        let mut machine_family = None;
        let mut execution_class = None;
        let mut restart_policy = None;
        let mut migration_kind = None;
        let mut probe_mode = None;
        let mut guest_commands = Vec::new();
        let mut require_secure_boot = false;
        let mut telemetry = Vec::new();
        let mut numa_nodes = Vec::new();

        let mut index = 0;
        while index < args.len() {
            let flag = args[index].as_str();
            match flag {
                "--session" => {
                    session_id = Some(next_value(args, &mut index, flag)?);
                }
                "--instance" => {
                    instance_id = Some(next_value(args, &mut index, flag)?);
                }
                "--runner-mode" => {
                    let value = next_value(args, &mut index, flag)?;
                    runner_mode = Some(RunnerMode::parse(&value)?);
                }
                "--heartbeat-interval-ms" => {
                    let value = next_value(args, &mut index, flag)?;
                    heartbeat_interval_ms = Some(parse_u64(&value, "heartbeat_interval_ms")?);
                }
                "--max-heartbeats" => {
                    let value = next_value(args, &mut index, flag)?;
                    max_heartbeats = Some(parse_u64(&value, "max_heartbeats")?);
                }
                "--stop-sentinel" => {
                    stop_sentinel = Some(next_value(args, &mut index, flag)?);
                }
                "--ingress-http-bind" => {
                    ingress_http_bind = Some(next_value(args, &mut index, flag)?);
                }
                "--ingress-tcp-bind" => {
                    ingress_tcp_bind = Some(next_value(args, &mut index, flag)?);
                }
                "--ingress-udp-bind" => {
                    ingress_udp_bind = Some(next_value(args, &mut index, flag)?);
                }
                "--arch" => {
                    let value = next_value(args, &mut index, flag)?;
                    guest_architecture = Some(GuestArchitecture::parse(&value)?);
                }
                "--vcpu" => {
                    let value = next_value(args, &mut index, flag)?;
                    vcpu = Some(parse_u16(&value, "vcpu")?);
                }
                "--memory-mb" => {
                    let value = next_value(args, &mut index, flag)?;
                    memory_mb = Some(parse_u64(&value, "memory_mb")?);
                }
                "--memory-backing" => {
                    let value = next_value(args, &mut index, flag)?;
                    memory_backing = Some(MemoryBacking::parse(&value)?);
                }
                "--firmware" => {
                    firmware_profile = Some(next_value(args, &mut index, flag)?);
                }
                "--firmware-artifact" => {
                    firmware_artifact = Some(next_value(args, &mut index, flag)?);
                }
                "--disk" => {
                    disk_image = Some(next_value(args, &mut index, flag)?);
                }
                "--cdrom" => {
                    cdrom_image = Some(next_value(args, &mut index, flag)?);
                }
                "--boot-device" => {
                    let value = next_value(args, &mut index, flag)?;
                    boot_device = Some(BootDevice::parse(&value)?);
                }
                "--boot-path" => {
                    let value = next_value(args, &mut index, flag)?;
                    boot_path = Some(BootPath::parse(&value)?);
                }
                "--device-model" => {
                    let value = next_value(args, &mut index, flag)?;
                    device_model = Some(DeviceModel::parse(&value)?);
                }
                "--machine-family" => {
                    let value = next_value(args, &mut index, flag)?;
                    machine_family = Some(MachineFamily::parse(&value)?);
                }
                "--execution-class" => {
                    let value = next_value(args, &mut index, flag)?;
                    execution_class = Some(ExecutionClass::parse(&value)?);
                }
                "--restart-policy" => {
                    restart_policy = Some(next_value(args, &mut index, flag)?);
                }
                "--migration-kind" => {
                    migration_kind = Some(next_value(args, &mut index, flag)?);
                }
                "--probe-mode" => {
                    probe_mode = Some(normalize_probe_mode(&next_value(args, &mut index, flag)?)?);
                }
                "--guest-command" => {
                    guest_commands.push(next_value(args, &mut index, flag)?);
                }
                "--telemetry" => {
                    telemetry.push(next_value(args, &mut index, flag)?);
                }
                "--numa-node" => {
                    let value = next_value(args, &mut index, flag)?;
                    numa_nodes.push(parse_u8(&value, "numa_node")?);
                }
                "--secure-boot" => require_secure_boot = true,
                _ => {
                    return Err(PlatformError::invalid(format!(
                        "unknown runner flag `{flag}`"
                    )));
                }
            }
            index += 1;
        }

        Ok(Self {
            session_id: require_field(session_id, "session_id")?,
            instance_id: require_field(instance_id, "instance_id")?,
            runner_mode: runner_mode.unwrap_or(RunnerMode::OneShot),
            heartbeat_interval_ms: heartbeat_interval_ms.unwrap_or(1_000),
            max_heartbeats,
            stop_sentinel,
            ingress_http_bind,
            ingress_tcp_bind,
            ingress_udp_bind,
            guest_architecture: require_field(guest_architecture, "guest_architecture")?,
            vcpu: require_field(vcpu, "vcpu")?,
            memory_mb: require_field(memory_mb, "memory_mb")?,
            memory_backing: memory_backing.unwrap_or(MemoryBacking::FileBacked),
            firmware_profile: require_field(firmware_profile, "firmware_profile")?,
            firmware_artifact,
            disk_image: require_field(disk_image, "disk_image")?,
            cdrom_image,
            boot_device: require_field(boot_device, "boot_device")?,
            boot_path: require_field(boot_path, "boot_path")?,
            device_model: require_field(device_model, "device_model")?,
            machine_family: require_field(machine_family, "machine_family")?,
            execution_class: require_field(execution_class, "execution_class")?,
            restart_policy: require_field(restart_policy, "restart_policy")?,
            migration_kind: require_field(migration_kind, "migration_kind")?,
            probe_mode,
            guest_commands,
            require_secure_boot,
            telemetry,
            numa_nodes,
        })
    }
}

fn next_value(args: &[String], index: &mut usize, flag: &str) -> Result<String> {
    let next = args.get(*index + 1).cloned().ok_or_else(|| {
        PlatformError::invalid(format!("flag `{flag}` requires a following value"))
    })?;
    *index += 1;
    Ok(next)
}

fn parse_u16(value: &str, field: &'static str) -> Result<u16> {
    value.parse::<u16>().map_err(|error| {
        PlatformError::invalid(format!("invalid {field}")).with_detail(error.to_string())
    })
}

fn parse_u64(value: &str, field: &'static str) -> Result<u64> {
    value.parse::<u64>().map_err(|error| {
        PlatformError::invalid(format!("invalid {field}")).with_detail(error.to_string())
    })
}

fn parse_u8(value: &str, field: &'static str) -> Result<u8> {
    value.parse::<u8>().map_err(|error| {
        PlatformError::invalid(format!("invalid {field}")).with_detail(error.to_string())
    })
}

fn require_field<T>(value: Option<T>, field: &'static str) -> Result<T> {
    value.ok_or_else(|| PlatformError::invalid(format!("missing required field `{field}`")))
}

fn normalize_probe_mode(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "qemu_tcg" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "probe_mode must be `qemu_tcg` when provided",
        )),
    }
}

fn parse_contract_csv(value: &str, env_name: &'static str) -> Result<Vec<String>> {
    value
        .split(',')
        .map(|entry| {
            let normalized = entry.trim().to_ascii_lowercase();
            if normalized.is_empty() {
                return Err(PlatformError::invalid(format!(
                    "{env_name} may not contain empty values"
                )));
            }
            if !normalized.chars().all(|character| {
                character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || matches!(character, '_' | '-')
            }) {
                return Err(PlatformError::invalid(format!(
                    "{env_name} contains invalid token `{normalized}`"
                )));
            }
            Ok(normalized)
        })
        .collect()
}

fn validate_exact_contract_list(
    actual: &[String],
    expected: &[&str],
    env_name: &'static str,
) -> Result<()> {
    let actual_set = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if actual.len() != actual_set.len() {
        return Err(PlatformError::invalid(format!(
            "{env_name} may not contain duplicate values"
        )));
    }

    if actual.len() != expected.len()
        || actual
            .iter()
            .map(String::as_str)
            .zip(expected.iter().copied())
            .any(|(actual, expected)| actual != expected)
    {
        return Err(PlatformError::conflict(format!(
            "{env_name} must define `{}` in order",
            expected.join(",")
        ))
        .with_detail(format!("got `{}`", actual.join(","))));
    }
    Ok(())
}

fn validate_backend_env(value: Option<String>) -> Result<()> {
    match value.as_deref() {
        Some("software_dbt") | None => Ok(()),
        Some(other) => Err(PlatformError::conflict(format!(
            "runner only supports backend `{}`, got `{other}`",
            HypervisorBackend::SoftwareDbt.as_str()
        ))),
    }
}

fn validate_full_vm_contract(config: &RunnerConfig) -> Result<()> {
    if config.memory_backing != MemoryBacking::FileBacked {
        return Err(PlatformError::conflict(
            "software runner requires memory_backing=file_backed",
        ));
    }
    let normalized_firmware_profile = config.firmware_profile.trim().to_ascii_lowercase();
    if config.machine_family == MachineFamily::MicrovmLinux {
        if config.require_secure_boot {
            return Err(PlatformError::conflict(
                "software runner secure boot requires firmware-mediated full-vm execution",
            ));
        }
        if config.boot_path != BootPath::MicroVm {
            return Err(PlatformError::conflict(
                "software runner requires boot_path=microvm for microvm_linux direct-kernel execution",
            ));
        }
        if config.guest_architecture != GuestArchitecture::X86_64 {
            return Err(PlatformError::conflict(
                "software runner microvm_linux direct-kernel execution currently supports only x86_64 guests",
            ));
        }
        if config.boot_device != BootDevice::Disk || config.cdrom_image.is_some() {
            return Err(PlatformError::conflict(
                "software runner microvm_linux direct-kernel execution requires disk boot without cdrom install media",
            ));
        }
        return Ok(());
    }
    if config.require_secure_boot && normalized_firmware_profile != "uefi_secure" {
        return Err(PlatformError::conflict(
            "software runner secure boot requires firmware=uefi_secure",
        ));
    }
    match (
        config.guest_architecture,
        config.machine_family,
        config.boot_path,
    ) {
        (GuestArchitecture::X86_64, MachineFamily::GeneralPurposePci, BootPath::GeneralPurpose) => {
            Ok(())
        }
        (GuestArchitecture::Aarch64, MachineFamily::Aarch64Virt, BootPath::AppleVm) => {
            if config.device_model != DeviceModel::AppleIntegrated {
                return Err(PlatformError::conflict(
                    "software runner aarch64 full-vm execution requires device_model=apple_integrated",
                ));
            }
            Ok(())
        }
        (GuestArchitecture::X86_64, MachineFamily::GeneralPurposePci, _) => {
            Err(PlatformError::conflict(
                "software runner requires boot_path=general_purpose for x86_64 firmware-mediated full-vm execution",
            ))
        }
        (GuestArchitecture::Aarch64, MachineFamily::Aarch64Virt, _) => {
            Err(PlatformError::conflict(
                "software runner requires boot_path=apple_vm for aarch64 firmware-mediated full-vm execution",
            ))
        }
        _ => Err(PlatformError::conflict(
            "software runner machine_family does not match the requested full-vm guest architecture",
        )),
    }
}

fn validate_supervise_contract(config: &RunnerConfig) -> Result<()> {
    if config.probe_mode.is_some() {
        return Err(PlatformError::conflict(
            "runner_mode=supervise does not support probe_mode; use runner_mode=one_shot for probe harness execution",
        ));
    }
    Ok(())
}

fn runner_workspace_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
        .ok_or_else(|| PlatformError::unavailable("failed to derive workspace root"))
}

fn resolve_probe_path(root: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn maybe_local_execution_artifact_path(value: &str) -> Option<PathBuf> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(path) = trimmed.strip_prefix("file://") {
        let path = PathBuf::from(path);
        return path.is_absolute().then_some(path);
    }
    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        return Some(path);
    }
    None
}

fn staged_execution_artifact_bytes(role: &str, source: &str) -> Vec<u8> {
    let medium = match role {
        "install_media" => "iso9660",
        "primary_disk" => "raw",
        _ => "opaque",
    };
    let mut bytes =
        format!("uhost-runner-staged-{role}\nsource={source}\nmedium={medium}\n").into_bytes();
    while bytes.len() < 4096 {
        bytes.extend_from_slice(source.as_bytes());
        bytes.push(b'\n');
    }
    bytes
}

fn stage_local_execution_artifact(role: &str, source: &str) -> Result<String> {
    if maybe_local_execution_artifact_path(source).is_some() {
        return Ok(source.to_owned());
    }
    if source.trim().starts_with("file://") {
        return Err(PlatformError::conflict(format!(
            "software-backed VM execution requires a local absolute path or file:// URI for {role} artifact"
        ))
        .with_detail(source.to_owned()));
    }

    let staged_root = env::temp_dir().join("uhost-uvm-runner-local-artifacts");
    fs::create_dir_all(&staged_root).map_err(|error| {
        PlatformError::unavailable("failed to create staged execution artifact directory")
            .with_detail(error.to_string())
    })?;

    let digest = sha256_hex(format!("{role}:{source}").as_bytes());
    let extension = match role {
        "install_media" => "iso",
        "primary_disk" => "raw",
        _ => "bin",
    };
    let staged_path = staged_root.join(format!("{role}-{digest}.{extension}"));
    if !staged_path.exists() {
        fs::write(&staged_path, staged_execution_artifact_bytes(role, source)).map_err(
            |error| {
                PlatformError::unavailable("failed to write staged execution artifact")
                    .with_detail(error.to_string())
            },
        )?;
    }
    Ok(staged_path.to_string_lossy().into_owned())
}

fn localize_execution_artifacts(config: &RunnerConfig) -> Result<(String, Option<String>)> {
    let disk_image = stage_local_execution_artifact("primary_disk", &config.disk_image)?;
    let cdrom_image = config
        .cdrom_image
        .as_deref()
        .map(|source| stage_local_execution_artifact("install_media", source))
        .transpose()?;
    Ok((disk_image, cdrom_image))
}

fn run_worker<T, F>(contract: &RunnerExecutionContract, role: RunnerWorkerRole, run: F) -> Result<T>
where
    F: FnOnce(&RunnerWorkerSandboxContract) -> Result<T>,
{
    let worker_contract = contract.enforce_worker(role)?;
    run(&worker_contract)
}

fn run_supervisor_worker<T, F>(contract: &RunnerExecutionContract, run: F) -> Result<T>
where
    F: FnOnce(&RunnerWorkerSandboxContract) -> Result<T>,
{
    run_worker(contract, RunnerWorkerRole::Supervisor, run)
}

fn run_block_worker(
    contract: &RunnerExecutionContract,
    config: &RunnerConfig,
) -> Result<LocalizedExecutionArtifacts> {
    run_worker(contract, RunnerWorkerRole::Block, |_worker_contract| {
        let (disk_image, cdrom_image) = localize_execution_artifacts(config)?;
        Ok(LocalizedExecutionArtifacts {
            disk_image,
            cdrom_image,
        })
    })
}

fn build_machine_spec(
    config: &RunnerConfig,
    localized_artifacts: LocalizedExecutionArtifacts,
) -> Result<MachineSpec> {
    MachineSpec::new(
        config.machine_family,
        config.guest_architecture,
        config.vcpu,
        config.memory_mb,
        config.device_model,
        config.boot_path,
        config.firmware_profile.clone(),
        localized_artifacts.disk_image,
        localized_artifacts.cdrom_image,
        config.boot_device,
    )
}

fn run_core_worker(
    contract: &RunnerExecutionContract,
    config: &RunnerConfig,
    localized_artifacts: LocalizedExecutionArtifacts,
) -> Result<StartedRuntime> {
    run_worker(contract, RunnerWorkerRole::Core, |_worker_contract| {
        let machine = build_machine_spec(config, localized_artifacts)?;
        let spec = SoftVmRuntimeSpec::new(config.execution_class, machine)
            .with_secure_boot(config.require_secure_boot)
            .with_firmware_artifact(config.firmware_artifact.clone());
        let mut instance =
            SoftVmInstance::new_with_artifact_policy(spec, SoftVmArtifactPolicy::LocalFilesOnly)?;
        instance.start()?;
        let boot_witness = instance.boot_witness()?;
        let guest_command_results = config
            .guest_commands
            .iter()
            .map(|command| instance.run_guest_command(command))
            .collect::<Result<Vec<_>>>()?;
        Ok(StartedRuntime {
            instance,
            boot_witness,
            guest_command_results,
        })
    })
}

fn run_net_worker(
    contract: &RunnerExecutionContract,
    instance: &SoftVmInstance,
    guest_control_ready: bool,
) -> Result<NetWorkerObservation> {
    run_worker(contract, RunnerWorkerRole::Net, |_worker_contract| {
        let virtio_net_mmio_present = instance
            .execution
            .mmio_regions
            .iter()
            .any(|region| region.name == VIRTIO_NET_MMIO_REGION_NAME);
        Ok(NetWorkerObservation {
            virtio_net_mmio_present,
            guest_control_ready,
            host_relay_egress_ready: true,
            network_mode: String::from(SOFTWARE_DBT_NETWORK_MODE),
            internet_nat: true,
            ssh_available: false,
            guest_exec_route_available: false,
            egress_transport: String::from(SOFTWARE_DBT_EGRESS_TRANSPORT),
            ingress_transport: String::from(SOFTWARE_DBT_INGRESS_TRANSPORT),
            ingress_http_ready: false,
            ingress_tcp_ready: false,
            ingress_udp_ready: false,
        })
    })
}

fn capture_worker_observation_snapshot(
    contract: &RunnerExecutionContract,
    config: &RunnerConfig,
    instance: &SoftVmInstance,
    boot_witness: &SoftVmBootWitness,
) -> Result<RunnerWorkerObservationSnapshot> {
    let artifact_count = run_worker(contract, RunnerWorkerRole::Block, |_worker_contract| {
        Ok(instance.execution.boot_artifacts.len())
    })?;
    let net = run_net_worker(contract, instance, boot_witness.guest_control_ready)?;
    Ok(worker_observation_snapshot_from_values(
        config,
        artifact_count,
        net.virtio_net_mmio_present,
        net.guest_control_ready,
    ))
}

fn build_worker_manifest_state(
    contract: &RunnerExecutionContract,
    config: &RunnerConfig,
    phase: SoftVmPhase,
    guest_memory_bytes: u64,
    instance: &SoftVmInstance,
    boot_witness: &SoftVmBootWitness,
) -> Result<RunnerWorkerManifestState> {
    let worker_observation =
        capture_worker_observation_snapshot(contract, config, instance, boot_witness)?;
    build_worker_manifest_state_from_observation(
        contract,
        config,
        phase,
        guest_memory_bytes,
        worker_observation,
    )
}

fn worker_observation_snapshot_from_values(
    config: &RunnerConfig,
    artifact_count: usize,
    virtio_net_mmio_present: bool,
    guest_control_ready: bool,
) -> RunnerWorkerObservationSnapshot {
    RunnerWorkerObservationSnapshot {
        block: BlockWorkerObservation {
            artifact_count,
            disk_image: config.disk_image.clone(),
            cdrom_image: config.cdrom_image.clone(),
        },
        net: NetWorkerObservation {
            virtio_net_mmio_present,
            guest_control_ready,
            host_relay_egress_ready: true,
            network_mode: String::from(SOFTWARE_DBT_NETWORK_MODE),
            internet_nat: true,
            ssh_available: false,
            guest_exec_route_available: false,
            egress_transport: String::from(SOFTWARE_DBT_EGRESS_TRANSPORT),
            ingress_transport: String::from(SOFTWARE_DBT_INGRESS_TRANSPORT),
            ingress_http_ready: false,
            ingress_tcp_ready: false,
            ingress_udp_ready: false,
        },
    }
}

fn build_worker_manifest_state_from_observation(
    contract: &RunnerExecutionContract,
    config: &RunnerConfig,
    phase: SoftVmPhase,
    guest_memory_bytes: u64,
    worker_observation: RunnerWorkerObservationSnapshot,
) -> Result<RunnerWorkerManifestState> {
    let guest_control_ready = worker_observation.net.guest_control_ready;
    let workers = build_worker_manifest(
        config,
        contract,
        phase,
        guest_memory_bytes,
        &worker_observation,
    )?;
    let manifest_fingerprint = build_worker_manifest_fingerprint(&workers, guest_control_ready)?;
    Ok(RunnerWorkerManifestState {
        workers,
        guest_control_ready,
        manifest_version: RUNNER_WORKER_MANIFEST_VERSION,
        manifest_fingerprint,
    })
}

fn build_worker_manifest_fingerprint(
    workers: &[serde_json::Value],
    guest_control_ready: bool,
) -> Result<String> {
    let payload = serde_json::json!({
        "version": RUNNER_WORKER_MANIFEST_VERSION,
        "guest_control_ready": guest_control_ready,
        "workers": workers,
    });
    let bytes = serde_json::to_vec(&payload).map_err(|error| {
        PlatformError::invalid("failed to serialize runner worker manifest fingerprint")
            .with_detail(error.to_string())
    })?;
    Ok(sha256_hex(&bytes))
}

fn send_supervised_core_worker_update(
    update_tx: &mpsc::Sender<Result<SupervisedCoreWorkerUpdate>>,
    update: Result<SupervisedCoreWorkerUpdate>,
) -> Result<()> {
    update_tx.send(update).map_err(|_| {
        PlatformError::unavailable("supervised core worker state channel disconnected")
    })
}

fn run_supervised_core_worker_loop(
    contract: RunnerExecutionContract,
    config: RunnerConfig,
    localized_artifacts: LocalizedExecutionArtifacts,
    command_rx: mpsc::Receiver<SupervisedCoreWorkerCommand>,
    update_tx: mpsc::Sender<Result<SupervisedCoreWorkerUpdate>>,
) -> Result<()> {
    // The supervision protocol is ordered on purpose: emit one `Started`, then
    // zero or more `Heartbeat` updates, and finally `Stopped` or an error. On
    // channel disconnect we only attempt shutdown if the runtime still owns a
    // running instance.
    let mut runtime = match run_core_worker(&contract, &config, localized_artifacts) {
        Ok(runtime) => runtime,
        Err(error) => {
            send_supervised_core_worker_update(&update_tx, Err(error))?;
            return Ok(());
        }
    };
    let configured_guest_memory_bytes = runtime.instance.memory.guest_memory_bytes;
    let guest_control = match runtime.instance.guest_control() {
        Ok(guest_control) => guest_control,
        Err(error) => {
            send_supervised_core_worker_update(&update_tx, Err(error))?;
            return Ok(());
        }
    };
    let worker_manifest = match build_worker_manifest_state(
        &contract,
        &config,
        runtime.instance.phase,
        configured_guest_memory_bytes,
        &runtime.instance,
        &runtime.boot_witness,
    ) {
        Ok(worker_manifest) => worker_manifest,
        Err(error) => {
            send_supervised_core_worker_update(&update_tx, Err(error))?;
            return Ok(());
        }
    };
    send_supervised_core_worker_update(
        &update_tx,
        Ok(SupervisedCoreWorkerUpdate::Started(
            SupervisedCoreWorkerStarted {
                phase: runtime.instance.phase,
                configured_guest_memory_bytes,
                boot_witness: runtime.boot_witness.clone(),
                guest_command_results: runtime.guest_command_results.clone(),
                guest_control,
                worker_manifest: worker_manifest.clone(),
            },
        )),
    )?;

    loop {
        match command_rx.recv() {
            Ok(SupervisedCoreWorkerCommand::Heartbeat) => {
                let heartbeat = runtime.instance.heartbeat();
                let guest_control = runtime.instance.guest_control()?;
                let worker_manifest = build_worker_manifest_state(
                    &contract,
                    &config,
                    runtime.instance.phase,
                    heartbeat.guest_memory_bytes,
                    &runtime.instance,
                    &runtime.boot_witness,
                )?;
                send_supervised_core_worker_update(
                    &update_tx,
                    Ok(SupervisedCoreWorkerUpdate::Heartbeat(
                        SupervisedCoreWorkerHeartbeat {
                            phase: runtime.instance.phase,
                            heartbeat,
                            guest_control,
                            worker_manifest,
                        },
                    )),
                )?;
            }
            Ok(SupervisedCoreWorkerCommand::Stop) => {
                match runtime.instance.stop() {
                    Ok(()) => {
                        let guest_control = runtime.instance.guest_control()?;
                        let worker_manifest = build_worker_manifest_state(
                            &contract,
                            &config,
                            runtime.instance.phase,
                            configured_guest_memory_bytes,
                            &runtime.instance,
                            &runtime.boot_witness,
                        )?;
                        send_supervised_core_worker_update(
                            &update_tx,
                            Ok(SupervisedCoreWorkerUpdate::Stopped(
                                SupervisedCoreWorkerStopped {
                                    phase: runtime.instance.phase,
                                    final_heartbeat_sequence: runtime.instance.heartbeat_sequence,
                                    configured_guest_memory_bytes,
                                    boot_witness: runtime.boot_witness.clone(),
                                    guest_control,
                                    worker_manifest,
                                },
                            )),
                        )?;
                    }
                    Err(error) => {
                        send_supervised_core_worker_update(&update_tx, Err(error))?;
                    }
                }
                return Ok(());
            }
            Err(_) => {
                if runtime.instance.phase == SoftVmPhase::Running {
                    let _ = runtime.instance.stop();
                }
                return Ok(());
            }
        }
    }
}

fn spawn_supervised_core_worker(
    contract: &RunnerExecutionContract,
    config: &RunnerConfig,
    localized_artifacts: LocalizedExecutionArtifacts,
) -> Result<SupervisedCoreWorkerHandle> {
    contract.enforce_worker(RunnerWorkerRole::Core)?;
    let (command_tx, command_rx) = mpsc::channel();
    let (update_tx, update_rx) = mpsc::channel();
    let contract = contract.clone();
    let config = config.clone();
    let join_handle = thread::spawn(move || {
        run_supervised_core_worker_loop(
            contract,
            config,
            localized_artifacts,
            command_rx,
            update_tx,
        )
    });
    Ok(SupervisedCoreWorkerHandle {
        command_tx,
        update_rx,
        join_handle: Some(join_handle),
    })
}

fn spawn_control_reader() -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let command = line.trim().to_ascii_lowercase();
                    if !command.is_empty() && tx.send(command).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

fn is_stop_command(command: &str) -> bool {
    matches!(command, "stop" | "shutdown" | "exit")
}

fn emit_json_line(value: serde_json::Value) -> Result<()> {
    let rendered = serde_json::to_string(&value).map_err(|error| {
        PlatformError::invalid("failed to serialize runner stream event")
            .with_detail(error.to_string())
    })?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{rendered}").map_err(|error| {
        PlatformError::unavailable("failed to write runner stream event")
            .with_detail(error.to_string())
    })?;
    stdout.flush().map_err(|error| {
        PlatformError::unavailable("failed to flush runner stream event")
            .with_detail(error.to_string())
    })?;
    Ok(())
}

fn build_worker_manifest(
    config: &RunnerConfig,
    contract: &RunnerExecutionContract,
    phase: SoftVmPhase,
    guest_memory_bytes: u64,
    observation: &RunnerWorkerObservationSnapshot,
) -> Result<Vec<serde_json::Value>> {
    let observed_pid = std::process::id();
    contract
        .workers
        .iter()
        .map(|worker| {
            let sandbox_contract = contract.enforce_worker(*worker)?;
            let detail = match worker {
                RunnerWorkerRole::Supervisor => serde_json::json!({
                    "runner_mode": config.runner_mode.as_str(),
                    "heartbeat_interval_ms": config.heartbeat_interval_ms,
                    "core_control_path": match config.runner_mode {
                        RunnerMode::OneShot => "direct_call",
                        RunnerMode::Supervise => "inproc_mpsc_v1",
                    },
                }),
                RunnerWorkerRole::Core => serde_json::json!({
                    "vcpu": config.vcpu,
                    "guest_memory_bytes": guest_memory_bytes,
                    "memory_backing": config.memory_backing.as_str(),
                    "instance_ownership": match config.runner_mode {
                        RunnerMode::OneShot => "call_scoped",
                        RunnerMode::Supervise => "thread_owned",
                    },
                }),
                RunnerWorkerRole::Block => serde_json::json!({
                    "artifact_count": observation.block.artifact_count,
                    "disk_image": observation.block.disk_image.as_str(),
                    "cdrom_image": observation.block.cdrom_image.as_deref(),
                }),
                RunnerWorkerRole::Net => serde_json::json!({
                    "virtio_net_mmio_present": observation.net.virtio_net_mmio_present,
                    "guest_control_ready": observation.net.guest_control_ready,
                    "host_relay_egress_ready": observation.net.host_relay_egress_ready,
                    "network_mode": observation.net.network_mode,
                    "internet_nat": observation.net.internet_nat,
                    "ssh_available": observation.net.ssh_available,
                    "guest_exec_route_available": observation.net.guest_exec_route_available,
                    "egress_transport": observation.net.egress_transport,
                    "ingress_transport": observation.net.ingress_transport,
                    "ingress_http_ready": observation.net.ingress_http_ready,
                    "ingress_tcp_ready": observation.net.ingress_tcp_ready,
                    "ingress_udp_ready": observation.net.ingress_udp_ready,
                }),
            };
            Ok(serde_json::json!({
                "name": worker.as_str(),
                "state": worker.state_for_phase(phase),
                "process_binding": worker.process_binding(),
                "observed_pid": observed_pid,
                "sandbox_layers": sandbox_contract.sandbox_layers(),
                "sandbox_enforcement_mode": RUNNER_SANDBOX_ENFORCEMENT_MODE,
                "sandbox_contract_source": RUNNER_SANDBOX_CONTRACT_SOURCE,
                "seccomp_profile": worker.seccomp_profile(),
                "execution_scope": worker.execution_scope(),
                "detail": detail,
            }))
        })
        .collect()
}

fn matching_lines(text: &str, patterns: &[&str], limit: usize) -> Vec<String> {
    let patterns = patterns
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut lines = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized = trimmed.to_ascii_lowercase();
        if patterns.iter().any(|pattern| normalized.contains(pattern)) {
            lines.push(trimmed.to_owned());
            if lines.len() >= limit {
                break;
            }
        }
    }
    lines
}

fn machine_virtio_net_mmio_present(machine: &MachineSpec) -> Result<bool> {
    Ok(machine
        .memory_layout()?
        .topology
        .device_by_kind(VIRTIO_NET_MMIO_REGION_NAME)
        .is_some())
}

fn qemu_tcg_probe_backend(machine: &MachineSpec) -> String {
    format!("qemu-tcg-{}", machine.guest_architecture)
}

fn qemu_tcg_probe_artifact_count(machine: &MachineSpec) -> usize {
    2 + usize::from(machine.boot.cdrom_image.is_some())
}

fn qemu_tcg_supported_power_events(machine: &MachineSpec) -> Vec<String> {
    if machine.boot.medium == "firmware" {
        vec![String::from("poweroff"), String::from("reboot")]
    } else {
        Vec::new()
    }
}

fn qemu_tcg_observed_power_events(bios_text: &str, kernel_text: &str) -> Vec<String> {
    let combined = [bios_text, kernel_text].join("\n").to_ascii_lowercase();
    let mut events = Vec::new();
    if combined.contains("reboot: power down")
        || combined.contains("system halted")
        || combined.contains("powering down")
    {
        events.push(String::from("poweroff"));
    }
    if combined.contains("reboot: restarting system")
        || combined.contains("rebooting system")
        || combined.contains("system reboot")
    {
        events.push(String::from("reboot"));
    }
    events
}

fn qemu_tcg_ready_scenarios(
    boot_stages: &[String],
    guest_control_ready: bool,
    observed_power_events: &[String],
) -> Vec<String> {
    let mut scenarios = Vec::new();
    if !boot_stages.is_empty() {
        scenarios.push(String::from("cold_boot"));
    }
    if guest_control_ready
        || boot_stages.iter().any(|stage| {
            matches!(
                stage.as_str(),
                "userspace:target_reached"
                    | "console:login_prompt_detected"
                    | "native_control:ready"
                    | "primary_disk:handoff_complete"
                    | "installer_environment:ready"
            )
        })
    {
        scenarios.push(String::from("service_readiness"));
    }
    if !observed_power_events.is_empty() {
        scenarios.push(String::from("fault_recovery"));
    }
    scenarios
}

fn qemu_tcg_generated_validation_target(machine: &MachineSpec) -> &'static str {
    if machine.guest_architecture == GuestArchitecture::Aarch64.as_str() {
        "apple_mac_studio_m1_pro_sim"
    } else {
        "ubuntu_22_04_vm"
    }
}

fn qemu_tcg_generated_validation_workload_class(target: &str) -> String {
    format!("generated_validation_{target}")
}

fn qemu_tcg_generated_validation_guest_run_lineage(target: &str) -> Option<String> {
    (target != "host").then(|| format!("{QEMU_TCG_GENERATED_VALIDATION_BUNDLE}_{target}"))
}

fn qemu_tcg_generated_validation_reference_hints(probe: &serde_json::Value) -> Vec<String> {
    ["raw_log", "text_log", "kernel_log"]
        .into_iter()
        .filter_map(|field| probe.get(field).and_then(serde_json::Value::as_str))
        .map(String::from)
        .collect()
}

fn qemu_tcg_generated_validation_projection(
    machine: &MachineSpec,
    probe_backend: &str,
    probe_evidence_mode: &str,
    measurement_mode: &str,
    ready_scenarios: &[String],
    probe: &serde_json::Value,
) -> serde_json::Value {
    let target = qemu_tcg_generated_validation_target(machine);
    let boot_surface = if machine.boot.primary_boot_device == "cdrom" {
        "install_media"
    } else {
        "disk"
    };
    serde_json::json!({
        "bundle": QEMU_TCG_GENERATED_VALIDATION_BUNDLE,
        "target": target,
        "workload_class": qemu_tcg_generated_validation_workload_class(target),
        "guest_run_lineage": qemu_tcg_generated_validation_guest_run_lineage(target),
        "measurement_mode": measurement_mode,
        "benchmark_ready_scenarios": ready_scenarios,
        "reference_hints": qemu_tcg_generated_validation_reference_hints(probe),
        "scenario_rows": ready_scenarios
            .iter()
            .map(|scenario| {
                serde_json::json!({
                    "scenario": scenario,
                    "source_engine": "qemu",
                    "observe_engine": "qemu",
                    "backend": probe_backend,
                    "measurement_mode": measurement_mode,
                })
            })
            .collect::<Vec<_>>(),
        "notes": {
            "probe_backend": probe_backend,
            "probe_evidence_mode": probe_evidence_mode,
            "boot_surface": boot_surface,
        },
    })
}

fn qemu_tcg_conformance_payload(
    machine: &MachineSpec,
    probe_backend: &str,
    probe_evidence_mode: &str,
    measurement_mode: &str,
    ready_scenarios: &[String],
    supported_power_events: &[String],
    observed_power_events: &[String],
    probe: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "engine": "qemu",
        "backend": probe_backend,
        "ingestion_path": "generated_validation_artifacts",
        "measurement_mode": measurement_mode,
        "boot_surface": if machine.boot.primary_boot_device == "cdrom" {
            "install_media"
        } else {
            "disk"
        },
        "ready_scenarios": ready_scenarios,
        "supported_power_events": supported_power_events,
        "observed_power_events": observed_power_events,
        "generated_validation_projection": qemu_tcg_generated_validation_projection(
            machine,
            probe_backend,
            probe_evidence_mode,
            measurement_mode,
            ready_scenarios,
            probe,
        ),
        "coverage": {
            "disk_boot": machine.boot.primary_boot_device == "disk",
            "install_media_boot": machine.boot.primary_boot_device == "cdrom",
            "aarch64": machine.guest_architecture == GuestArchitecture::Aarch64.as_str(),
            "observe_side_ready": !ready_scenarios.is_empty(),
            "reboot": supported_power_events.iter().any(|event| event == "reboot"),
            "poweroff": supported_power_events.iter().any(|event| event == "poweroff"),
        },
    })
}

struct QemuTcgProbeObservation {
    phase: SoftVmPhase,
    guest_memory_bytes: u64,
    artifact_count: usize,
    virtio_net_mmio_present: bool,
    probe_evidence_mode: &'static str,
    boot_stages: Vec<String>,
    console_trace: Vec<String>,
    guest_control_ready: bool,
    power_events: Vec<String>,
    measurement_mode: &'static str,
    probe: serde_json::Value,
}

fn qemu_tcg_probe_output_from_observation(
    contract: &RunnerExecutionContract,
    config: &RunnerConfig,
    machine: &MachineSpec,
    observation: QemuTcgProbeObservation,
) -> Result<serde_json::Value> {
    let QemuTcgProbeObservation {
        phase,
        guest_memory_bytes,
        artifact_count,
        virtio_net_mmio_present,
        probe_evidence_mode,
        boot_stages,
        console_trace,
        guest_control_ready,
        power_events,
        measurement_mode,
        probe,
    } = observation;
    let worker_manifest = build_worker_manifest_state_from_observation(
        contract,
        config,
        phase,
        guest_memory_bytes,
        worker_observation_snapshot_from_values(
            config,
            artifact_count,
            virtio_net_mmio_present,
            guest_control_ready,
        ),
    )?;
    let probe_backend = qemu_tcg_probe_backend(machine);
    let supported_power_events = qemu_tcg_supported_power_events(machine);
    let ready_scenarios =
        qemu_tcg_ready_scenarios(&boot_stages, guest_control_ready, &power_events);
    Ok(serde_json::json!({
        "session_id": config.session_id,
        "instance_id": config.instance_id,
        "backend": HypervisorBackend::SoftwareDbt.as_str(),
        "probe_mode": "qemu_tcg",
        "probe_backend": probe_backend,
        "probe_evidence_mode": probe_evidence_mode,
        "phase": phase.as_str(),
        "heartbeat_sequence": 1,
        "guest_memory_bytes": guest_memory_bytes,
        "vcpu": config.vcpu,
        "machine_family": machine.machine_family.clone(),
        "guest_architecture": machine.guest_architecture.clone(),
        "boot_path": machine.boot_path.clone(),
        "device_model": machine.device_model.clone(),
        "boot_medium": machine.boot.medium.clone(),
        "firmware_profile": machine.boot.firmware_profile.clone(),
        "primary_boot_device": machine.boot.primary_boot_device.clone(),
        "disk_image": machine.boot.disk_image.clone(),
        "cdrom_image": machine.boot.cdrom_image.clone(),
        "memory_backing": config.memory_backing.as_str(),
        "execution_class": config.execution_class.as_str(),
        "restart_policy": config.restart_policy,
        "migration_kind": config.migration_kind,
        "secure_boot": config.require_secure_boot,
        "secure_boot_measurements": Vec::<String>::new(),
        "sandbox_layers": contract.sandbox_layers,
        "sandbox_enforcement_mode": RUNNER_SANDBOX_ENFORCEMENT_MODE,
        "sandbox_contract_source": RUNNER_SANDBOX_CONTRACT_SOURCE,
        "worker_states": contract.worker_states(phase),
        "worker_manifest_version": worker_manifest.manifest_version,
        "worker_manifest_fingerprint": worker_manifest.manifest_fingerprint,
        "workers": worker_manifest.workers,
        "boot_stages": boot_stages,
        "console_trace": console_trace,
        "guest_control_ready": guest_control_ready,
        "power_events": power_events,
        "qemu_tcg_conformance": qemu_tcg_conformance_payload(
            machine,
            qemu_tcg_probe_backend(machine).as_str(),
            probe_evidence_mode,
            measurement_mode,
            &ready_scenarios,
            &supported_power_events,
            &power_events,
            &probe,
        ),
        "telemetry": config.telemetry,
        "numa_nodes": config.numa_nodes,
        "probe": probe,
    }))
}

fn qemu_tcg_probe_output_from_harness_artifacts(
    contract: &RunnerExecutionContract,
    config: &RunnerConfig,
    machine: &MachineSpec,
    summary: serde_json::Value,
    bios_text: &str,
    kernel_text: &str,
) -> Result<serde_json::Value> {
    let boot_menu_detected = summary
        .get("boot_menu_detected")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let bios_installer_strings_detected = summary
        .get("bios_installer_strings_detected")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let kernel_boot_text_detected = summary
        .get("kernel_boot_text_detected")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let kernel_installer_progress_detected = summary
        .get("kernel_installer_progress_detected")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let casper_cdrom_mismatch_detected = summary
        .get("casper_cdrom_mismatch_detected")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let kernel_panic_detected = summary
        .get("kernel_panic_detected")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let userspace_targets_detected = summary
        .get("userspace_targets_detected")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let serial_login_prompt_detected = summary
        .get("serial_login_prompt_detected")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    let mut boot_stages = Vec::new();
    if boot_menu_detected {
        boot_stages.push(String::from("bios:grub_menu_observed"));
    }
    if bios_installer_strings_detected {
        boot_stages.push(String::from("bios:installer_entry_observed"));
    }
    if kernel_boot_text_detected {
        boot_stages.push(String::from("kernel:boot_text_observed"));
    }
    if kernel_installer_progress_detected {
        boot_stages.push(String::from("userspace:installer_progress_observed"));
    }
    if userspace_targets_detected {
        boot_stages.push(String::from("userspace:target_reached"));
    }
    if serial_login_prompt_detected {
        boot_stages.push(String::from("console:login_prompt_detected"));
    }
    if casper_cdrom_mismatch_detected {
        boot_stages.push(String::from("casper:cdrom_mismatch"));
    }
    if kernel_panic_detected {
        boot_stages.push(String::from("kernel:panic_detected"));
    }
    let power_events = qemu_tcg_observed_power_events(bios_text, kernel_text);
    if power_events.iter().any(|event| event == "poweroff") {
        boot_stages.push(String::from("power:poweroff_observed"));
    }
    if power_events.iter().any(|event| event == "reboot") {
        boot_stages.push(String::from("power:reboot_observed"));
    }

    let mut console_trace = matching_lines(
        bios_text,
        &[
            "SeaBIOS",
            "Booting from DVD/CD",
            "GNU GRUB",
            "Try or Install Ubuntu",
        ],
        6,
    );
    console_trace.extend(matching_lines(
        kernel_text,
        &[
            "Linux version",
            "Mounting root file system",
            "Started systemd-journald.service",
            "cloud-init",
            "Kernel panic",
            "Reached target",
            "login:",
            "can't open /dev/sr0",
            "reboot: Restarting system",
            "reboot: Power down",
            "system halted",
        ],
        8,
    ));

    let guest_control_ready = userspace_targets_detected || serial_login_prompt_detected;
    let phase = if guest_control_ready || kernel_boot_text_detected {
        SoftVmPhase::Running
    } else if boot_menu_detected {
        SoftVmPhase::Prepared
    } else {
        SoftVmPhase::Created
    };
    let memory = machine.memory_layout()?;
    qemu_tcg_probe_output_from_observation(
        contract,
        config,
        machine,
        QemuTcgProbeObservation {
            phase,
            guest_memory_bytes: memory.guest_memory_bytes,
            artifact_count: qemu_tcg_probe_artifact_count(machine),
            virtio_net_mmio_present: machine_virtio_net_mmio_present(machine)?,
            probe_evidence_mode: "harness_logs",
            boot_stages,
            console_trace,
            guest_control_ready,
            power_events,
            measurement_mode: "hybrid",
            probe: summary,
        },
    )
}

fn qemu_tcg_probe_harness_supported(config: &RunnerConfig, machine: &MachineSpec) -> bool {
    config.guest_architecture == GuestArchitecture::X86_64
        && config.machine_family == MachineFamily::GeneralPurposePci
        && config.boot_path == BootPath::GeneralPurpose
        && config.boot_device == BootDevice::Cdrom
        && config.cdrom_image.is_some()
        && machine.boot.medium == "firmware"
        && config.firmware_profile.trim().eq_ignore_ascii_case("bios")
}

fn qemu_tcg_probe_output_from_modeled_runtime(
    contract: &RunnerExecutionContract,
    config: &RunnerConfig,
    localized_artifacts: LocalizedExecutionArtifacts,
    machine: &MachineSpec,
) -> Result<serde_json::Value> {
    let mut runtime = run_core_worker(contract, config, localized_artifacts)?;
    runtime.instance.stop()?;
    runtime.instance.start()?;
    let boot_witness = runtime.instance.boot_witness()?;
    let mut boot_stages = boot_witness.stages.clone();
    boot_stages.push(String::from("power:poweroff_observed"));
    boot_stages.push(String::from("power:reboot_observed"));
    boot_stages.push(String::from("probe:qemu_tcg:modeled"));
    let mut console_trace = boot_witness.console_trace.clone();
    console_trace.push(String::from(
        "Modeled qemu_tcg poweroff completed through software_dbt lifecycle",
    ));
    console_trace.push(String::from(
        "Modeled qemu_tcg reboot completed through software_dbt lifecycle",
    ));
    let power_events = vec![String::from("poweroff"), String::from("reboot")];
    qemu_tcg_probe_output_from_observation(
        contract,
        config,
        machine,
        QemuTcgProbeObservation {
            phase: runtime.instance.phase,
            guest_memory_bytes: runtime.instance.memory.guest_memory_bytes,
            artifact_count: runtime.instance.execution.boot_artifacts.len(),
            virtio_net_mmio_present: runtime
                .instance
                .execution
                .mmio_regions
                .iter()
                .any(|region| region.name == VIRTIO_NET_MMIO_REGION_NAME),
            probe_evidence_mode: "modeled_softvm",
            boot_stages,
            console_trace,
            guest_control_ready: boot_witness.guest_control_ready,
            power_events,
            measurement_mode: "modeled",
            probe: serde_json::json!({
                "source": "softvm",
                "modeled": true,
                "artifact_count": runtime.instance.execution.boot_artifacts.len(),
                "guest_command_results": runtime.guest_command_results.len(),
                "boot_witness_stage_count": boot_witness.stages.len(),
            }),
        },
    )
}

fn qemu_tcg_probe_output(
    contract: &RunnerExecutionContract,
    config: &RunnerConfig,
    localized_artifacts: LocalizedExecutionArtifacts,
) -> Result<serde_json::Value> {
    // `qemu_tcg` probe mode has two branches: use the real harness only for the
    // supported firmware-mediated full-VM contract, otherwise fall back to the
    // modeled SoftVM-derived evidence path instead of implying a direct probe
    // was possible.
    let machine = build_machine_spec(config, localized_artifacts.clone())?;
    if machine.boot.medium != "firmware" {
        return Err(PlatformError::conflict(
            "qemu_tcg probe mode requires a firmware-mediated full-vm machine contract",
        ));
    }
    if qemu_tcg_probe_harness_supported(config, &machine) {
        let root = runner_workspace_root()?;
        let status = Command::new("sh")
            .arg(root.join("scripts/run-qemu-tcg-boot-probe.sh"))
            .current_dir(&root)
            .status()
            .map_err(|error| {
                PlatformError::unavailable("failed to execute qemu_tcg probe harness")
                    .with_detail(error.to_string())
            })?;
        if !status.success() {
            return Err(PlatformError::unavailable(
                "qemu_tcg probe harness exited unsuccessfully",
            ));
        }

        let summary_path =
            root.join("docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.json");
        let summary_bytes = fs::read(&summary_path).map_err(|error| {
            PlatformError::unavailable("failed to read qemu_tcg probe summary")
                .with_detail(error.to_string())
        })?;
        let summary: serde_json::Value =
            serde_json::from_slice(&summary_bytes).map_err(|error| {
                PlatformError::invalid("failed to parse qemu_tcg probe summary")
                    .with_detail(error.to_string())
            })?;

        let text_log = summary
            .get("text_log")
            .and_then(serde_json::Value::as_str)
            .map(|value| resolve_probe_path(&root, value))
            .ok_or_else(|| PlatformError::invalid("qemu_tcg probe summary is missing text_log"))?;
        let kernel_log = summary
            .get("kernel_log")
            .and_then(serde_json::Value::as_str)
            .map(|value| resolve_probe_path(&root, value))
            .ok_or_else(|| {
                PlatformError::invalid("qemu_tcg probe summary is missing kernel_log")
            })?;
        let bios_text = fs::read_to_string(&text_log).map_err(|error| {
            PlatformError::unavailable("failed to read qemu_tcg BIOS probe log")
                .with_detail(error.to_string())
        })?;
        let kernel_text = fs::read_to_string(&kernel_log).map_err(|error| {
            PlatformError::unavailable("failed to read qemu_tcg kernel probe log")
                .with_detail(error.to_string())
        })?;
        return qemu_tcg_probe_output_from_harness_artifacts(
            contract,
            config,
            &machine,
            summary,
            &bios_text,
            &kernel_text,
        );
    }
    qemu_tcg_probe_output_from_modeled_runtime(contract, config, localized_artifacts, &machine)
}

fn guest_control_file<'a>(control: &'a SoftVmGuestControl, path: &str) -> Option<&'a str> {
    control
        .files
        .iter()
        .find(|file| file.path == path)
        .map(|file| file.contents.as_str())
}

impl ManagedHttpIngress {
    fn start(session_id: &str, requested_bind: &str, control: &SoftVmGuestControl) -> Result<Self> {
        let bind = normalize_socket_bind(requested_bind, "managed UVM http ingress bind")?;
        let root = managed_http_ingress_root(session_id);
        sync_http_ingress_webroot(&root, control)?;
        let listener = TcpListener::bind(bind).map_err(|error| {
            PlatformError::unavailable("failed to bind managed UVM ingress listener")
                .with_detail(error.to_string())
        })?;
        listener.set_nonblocking(true).map_err(|error| {
            PlatformError::unavailable("failed to configure managed UVM ingress listener")
                .with_detail(error.to_string())
        })?;
        let local_addr = listener.local_addr().map_err(|error| {
            PlatformError::unavailable("failed to inspect managed UVM ingress listener")
                .with_detail(error.to_string())
        })?;
        let stop_flag = Arc::new(AtomicBool::new(false));
        let worker_stop_flag = Arc::clone(&stop_flag);
        let worker_root = root.clone();
        let join_handle = thread::spawn(move || {
            run_managed_http_ingress_listener(listener, worker_root, worker_stop_flag)
        });
        Ok(Self {
            state: ManagedIngressState {
                http_bind: local_addr.to_string(),
                http_url: format!("http://{local_addr}"),
                web_root: root,
                ready: true,
            },
            stop_flag,
            join_handle: Some(join_handle),
        })
    }

    fn sync(&self, control: &SoftVmGuestControl) -> Result<()> {
        sync_http_ingress_webroot(&self.state.web_root, control)
    }

    fn state(&self) -> &ManagedIngressState {
        &self.state
    }

    fn stop(&mut self) -> Result<ManagedIngressState> {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(join_handle) = self.join_handle.take() {
            match join_handle.join() {
                Ok(result) => result?,
                Err(_) => {
                    return Err(PlatformError::unavailable(
                        "managed UVM ingress thread panicked",
                    ));
                }
            }
        }
        let mut state = self.state.clone();
        state.ready = false;
        Ok(state)
    }
}

impl ManagedTcpIngressMode {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "echo" => Ok(Self::Echo),
            "static_response" | "static" => Ok(Self::StaticResponse),
            _ => Err(PlatformError::invalid(
                "managed UVM tcp ingress mode must be `echo` or `static_response`",
            )),
        }
    }
}

impl ManagedTcpIngress {
    fn start(requested_bind: &str, control: &SoftVmGuestControl) -> Result<Self> {
        let service = managed_tcp_ingress_service_config(control, requested_bind)?;
        let bind = normalize_socket_bind(service.bind.as_str(), "managed UVM tcp ingress bind")?;
        let listener = TcpListener::bind(bind).map_err(|error| {
            PlatformError::unavailable("failed to bind managed UVM tcp ingress listener")
                .with_detail(error.to_string())
        })?;
        listener.set_nonblocking(true).map_err(|error| {
            PlatformError::unavailable("failed to configure managed UVM tcp ingress listener")
                .with_detail(error.to_string())
        })?;
        let local_addr = listener.local_addr().map_err(|error| {
            PlatformError::unavailable("failed to inspect managed UVM tcp ingress listener")
                .with_detail(error.to_string())
        })?;
        let stop_flag = Arc::new(AtomicBool::new(false));
        let worker_stop_flag = Arc::clone(&stop_flag);
        let shared_service = Arc::new(Mutex::new(service.clone()));
        let worker_service = Arc::clone(&shared_service);
        let join_handle = thread::spawn(move || {
            run_managed_tcp_ingress_listener(listener, worker_service, worker_stop_flag)
        });
        Ok(Self {
            state: ManagedTcpIngressState {
                tcp_bind: local_addr.to_string(),
                service_name: service.name.clone(),
                ready: true,
            },
            requested_bind: String::from(requested_bind),
            service: shared_service,
            stop_flag,
            join_handle: Some(join_handle),
        })
    }

    fn sync(&mut self, control: &SoftVmGuestControl) -> Result<()> {
        let service = managed_tcp_ingress_service_config(control, &self.requested_bind)?;
        let current_bind = self
            .service
            .lock()
            .ok()
            .map(|value| value.bind.clone())
            .unwrap_or_else(|| self.state.tcp_bind.clone());
        if current_bind != service.bind {
            let requested_bind = self.requested_bind.clone();
            let _ = self.stop()?;
            *self = Self::start(&requested_bind, control)?;
            return Ok(());
        }
        if let Ok(mut current) = self.service.lock() {
            *current = service.clone();
        }
        self.state.service_name = service.name;
        Ok(())
    }

    fn state(&self) -> &ManagedTcpIngressState {
        &self.state
    }

    fn stop(&mut self) -> Result<ManagedTcpIngressState> {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(join_handle) = self.join_handle.take() {
            match join_handle.join() {
                Ok(result) => result?,
                Err(_) => {
                    return Err(PlatformError::unavailable(
                        "managed UVM tcp ingress thread panicked",
                    ));
                }
            }
        }
        let mut state = self.state.clone();
        state.ready = false;
        Ok(state)
    }
}

fn managed_tcp_ingress_service_config(
    control: &SoftVmGuestControl,
    requested_bind: &str,
) -> Result<ManagedTcpIngressServiceConfig> {
    let service_name = guest_control_file(control, "/run/guest-ingress/tcp/default-service")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_TCP_INGRESS_SERVICE_NAME)
        .to_owned();
    let service_root = format!("/run/guest-ingress/tcp/services/{service_name}");
    let bind = guest_control_file(control, format!("{service_root}/bind").as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(requested_bind)
        .to_owned();
    let mode = guest_control_file(control, format!("{service_root}/mode").as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("echo");
    let banner = guest_control_file(control, format!("{service_root}/banner").as_str())
        .unwrap_or_default()
        .as_bytes()
        .to_vec();
    let response = guest_control_file(control, format!("{service_root}/response").as_str())
        .unwrap_or_default()
        .as_bytes()
        .to_vec();
    Ok(ManagedTcpIngressServiceConfig {
        name: service_name,
        bind,
        mode: ManagedTcpIngressMode::parse(mode)?,
        banner,
        response,
    })
}

fn run_managed_tcp_ingress_listener(
    listener: TcpListener,
    service: Arc<Mutex<ManagedTcpIngressServiceConfig>>,
    stop_flag: Arc<AtomicBool>,
) -> Result<()> {
    while !stop_flag.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let service = service
                    .lock()
                    .map(|value| value.clone())
                    .unwrap_or_else(|_| ManagedTcpIngressServiceConfig {
                        name: String::from(DEFAULT_TCP_INGRESS_SERVICE_NAME),
                        bind: String::from(SOFTWARE_DBT_DEFAULT_INGRESS_TCP_BIND),
                        mode: ManagedTcpIngressMode::Echo,
                        banner: Vec::new(),
                        response: Vec::new(),
                    });
                let _ = serve_managed_tcp_ingress_connection(stream, &service);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                return Err(PlatformError::unavailable(
                    "managed UVM tcp ingress listener failed to accept a connection",
                )
                .with_detail(error.to_string()));
            }
        }
    }
    Ok(())
}

fn serve_managed_tcp_ingress_connection(
    mut stream: TcpStream,
    service: &ManagedTcpIngressServiceConfig,
) -> Result<()> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| {
            PlatformError::unavailable("failed to configure managed UVM tcp ingress timeout")
                .with_detail(error.to_string())
        })?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| {
            PlatformError::unavailable("failed to configure managed UVM tcp ingress timeout")
                .with_detail(error.to_string())
        })?;
    if !service.banner.is_empty() {
        stream.write_all(&service.banner).map_err(|error| {
            PlatformError::unavailable("failed to write managed UVM tcp ingress banner")
                .with_detail(error.to_string())
        })?;
    }
    let mut buffer = vec![0_u8; MAX_TCP_INGRESS_READ_BYTES];
    let read = match stream.read(&mut buffer) {
        Ok(read) => read,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            0
        }
        Err(error) => {
            return Err(PlatformError::unavailable(
                "failed to read managed UVM tcp ingress payload",
            )
            .with_detail(error.to_string()));
        }
    };
    let response = match service.mode {
        ManagedTcpIngressMode::Echo if read > 0 => Some(buffer[..read].to_vec()),
        ManagedTcpIngressMode::Echo => {
            (!service.response.is_empty()).then_some(service.response.clone())
        }
        ManagedTcpIngressMode::StaticResponse => Some(service.response.clone()),
    };
    if let Some(response) = response
        && !response.is_empty()
    {
        stream.write_all(&response).map_err(|error| {
            PlatformError::unavailable("failed to write managed UVM tcp ingress payload")
                .with_detail(error.to_string())
        })?;
    }
    stream.flush().map_err(|error| {
        PlatformError::unavailable("failed to flush managed UVM tcp ingress payload")
            .with_detail(error.to_string())
    })?;
    Ok(())
}

impl ManagedUdpIngressMode {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "echo" => Ok(Self::Echo),
            "static_response" | "static" => Ok(Self::StaticResponse),
            _ => Err(PlatformError::invalid(
                "managed UVM udp ingress mode must be `echo` or `static_response`",
            )),
        }
    }
}

impl ManagedUdpIngress {
    fn start(requested_bind: &str, control: &SoftVmGuestControl) -> Result<Self> {
        let service = managed_udp_ingress_service_config(control, requested_bind)?;
        let bind = normalize_socket_bind(service.bind.as_str(), "managed UVM udp ingress bind")?;
        let socket = UdpSocket::bind(bind).map_err(|error| {
            PlatformError::unavailable("failed to bind managed UVM udp ingress socket")
                .with_detail(error.to_string())
        })?;
        socket.set_nonblocking(true).map_err(|error| {
            PlatformError::unavailable("failed to configure managed UVM udp ingress socket")
                .with_detail(error.to_string())
        })?;
        let local_addr = socket.local_addr().map_err(|error| {
            PlatformError::unavailable("failed to inspect managed UVM udp ingress socket")
                .with_detail(error.to_string())
        })?;
        let stop_flag = Arc::new(AtomicBool::new(false));
        let worker_stop_flag = Arc::clone(&stop_flag);
        let shared_service = Arc::new(Mutex::new(service.clone()));
        let worker_service = Arc::clone(&shared_service);
        let join_handle = thread::spawn(move || {
            run_managed_udp_ingress_listener(socket, worker_service, worker_stop_flag)
        });
        Ok(Self {
            state: ManagedUdpIngressState {
                udp_bind: local_addr.to_string(),
                service_name: service.name.clone(),
                ready: true,
            },
            requested_bind: String::from(requested_bind),
            service: shared_service,
            stop_flag,
            join_handle: Some(join_handle),
        })
    }

    fn sync(&mut self, control: &SoftVmGuestControl) -> Result<()> {
        let service = managed_udp_ingress_service_config(control, &self.requested_bind)?;
        let current_bind = self
            .service
            .lock()
            .ok()
            .map(|value| value.bind.clone())
            .unwrap_or_else(|| self.state.udp_bind.clone());
        if current_bind != service.bind {
            let requested_bind = self.requested_bind.clone();
            let _ = self.stop()?;
            *self = Self::start(&requested_bind, control)?;
            return Ok(());
        }
        if let Ok(mut current) = self.service.lock() {
            *current = service.clone();
        }
        self.state.service_name = service.name;
        Ok(())
    }

    fn state(&self) -> &ManagedUdpIngressState {
        &self.state
    }

    fn stop(&mut self) -> Result<ManagedUdpIngressState> {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(join_handle) = self.join_handle.take() {
            match join_handle.join() {
                Ok(result) => result?,
                Err(_) => {
                    return Err(PlatformError::unavailable(
                        "managed UVM udp ingress thread panicked",
                    ));
                }
            }
        }
        let mut state = self.state.clone();
        state.ready = false;
        Ok(state)
    }
}

fn managed_udp_ingress_service_config(
    control: &SoftVmGuestControl,
    requested_bind: &str,
) -> Result<ManagedUdpIngressServiceConfig> {
    let service_name = guest_control_file(control, "/run/guest-ingress/udp/default-service")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_UDP_INGRESS_SERVICE_NAME)
        .to_owned();
    let service_root = format!("/run/guest-ingress/udp/services/{service_name}");
    let bind = guest_control_file(control, format!("{service_root}/bind").as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(requested_bind)
        .to_owned();
    let mode = guest_control_file(control, format!("{service_root}/mode").as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("echo");
    let response = guest_control_file(control, format!("{service_root}/response").as_str())
        .unwrap_or_default()
        .as_bytes()
        .to_vec();
    Ok(ManagedUdpIngressServiceConfig {
        name: service_name,
        bind,
        mode: ManagedUdpIngressMode::parse(mode)?,
        response,
    })
}

fn run_managed_udp_ingress_listener(
    socket: UdpSocket,
    service: Arc<Mutex<ManagedUdpIngressServiceConfig>>,
    stop_flag: Arc<AtomicBool>,
) -> Result<()> {
    let mut buffer = vec![0_u8; MAX_UDP_INGRESS_READ_BYTES];
    while !stop_flag.load(Ordering::SeqCst) {
        match socket.recv_from(&mut buffer) {
            Ok((read, peer)) => {
                let service = service
                    .lock()
                    .map(|value| value.clone())
                    .unwrap_or_else(|_| ManagedUdpIngressServiceConfig {
                        name: String::from(DEFAULT_UDP_INGRESS_SERVICE_NAME),
                        bind: String::from(SOFTWARE_DBT_DEFAULT_INGRESS_UDP_BIND),
                        mode: ManagedUdpIngressMode::Echo,
                        response: Vec::new(),
                    });
                let response = match service.mode {
                    ManagedUdpIngressMode::Echo if read > 0 => Some(buffer[..read].to_vec()),
                    ManagedUdpIngressMode::Echo => {
                        (!service.response.is_empty()).then_some(service.response.clone())
                    }
                    ManagedUdpIngressMode::StaticResponse => Some(service.response.clone()),
                };
                if let Some(response) = response
                    && !response.is_empty()
                {
                    let _ = socket.send_to(&response, peer);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                return Err(PlatformError::unavailable(
                    "managed UVM udp ingress listener failed to receive a datagram",
                )
                .with_detail(error.to_string()));
            }
        }
    }
    Ok(())
}

fn normalize_socket_bind(value: &str, field: &'static str) -> Result<SocketAddr> {
    value.trim().parse::<SocketAddr>().map_err(|error| {
        PlatformError::invalid(format!("{field} must be a socket address"))
            .with_detail(error.to_string())
    })
}

fn managed_http_ingress_root(session_id: &str) -> PathBuf {
    let root_nonce = MANAGED_INGRESS_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
    env::temp_dir()
        .join("uhost-managed-uvm-ingress")
        .join(format!("{session_id}-{}-{root_nonce}", std::process::id()))
        .join("webroot")
}

fn sync_http_ingress_webroot(root: &Path, control: &SoftVmGuestControl) -> Result<()> {
    if root.exists() {
        fs::remove_dir_all(root).map_err(|error| {
            PlatformError::unavailable("failed to reset managed UVM ingress mirror")
                .with_detail(error.to_string())
        })?;
    }
    fs::create_dir_all(root).map_err(|error| {
        PlatformError::unavailable("failed to create managed UVM ingress mirror")
            .with_detail(error.to_string())
    })?;
    for file in &control.files {
        let Some(relative) = ingress_relative_path(file.path.as_str()) else {
            continue;
        };
        let target = root.join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                PlatformError::unavailable("failed to prepare managed UVM ingress directory")
                    .with_detail(error.to_string())
            })?;
        }
        fs::write(&target, file.contents.as_bytes()).map_err(|error| {
            PlatformError::unavailable("failed to sync managed UVM ingress file")
                .with_detail(error.to_string())
        })?;
    }
    Ok(())
}

fn ingress_relative_path(path: &str) -> Option<PathBuf> {
    let relative = path.strip_prefix(&format!("{SOFTWARE_DBT_GUEST_WEB_ROOT}/"))?;
    let mut resolved = PathBuf::new();
    for segment in relative.split('/') {
        if segment.is_empty() || matches!(segment, "." | "..") {
            return None;
        }
        resolved.push(segment);
    }
    Some(resolved)
}

fn run_managed_http_ingress_listener(
    listener: TcpListener,
    web_root: PathBuf,
    stop_flag: Arc<AtomicBool>,
) -> Result<()> {
    while !stop_flag.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = serve_managed_http_ingress_connection(stream, &web_root);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                return Err(PlatformError::unavailable(
                    "managed UVM ingress listener failed to accept a connection",
                )
                .with_detail(error.to_string()));
            }
        }
    }
    Ok(())
}

fn serve_managed_http_ingress_connection(mut stream: TcpStream, web_root: &Path) -> Result<()> {
    let request = read_http_ingress_request(&mut stream)?;
    let response = build_http_ingress_response(&request, web_root);
    stream.write_all(response.as_bytes()).map_err(|error| {
        PlatformError::unavailable("failed to write managed UVM ingress response")
            .with_detail(error.to_string())
    })?;
    stream.flush().map_err(|error| {
        PlatformError::unavailable("failed to flush managed UVM ingress response")
            .with_detail(error.to_string())
    })?;
    Ok(())
}

fn read_http_ingress_request(stream: &mut TcpStream) -> Result<String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| {
            PlatformError::unavailable("failed to set managed UVM ingress read timeout")
                .with_detail(error.to_string())
        })?;
    let mut buffer = [0_u8; 1024];
    let mut request = Vec::new();
    loop {
        let read = stream.read(&mut buffer).map_err(|error| {
            PlatformError::unavailable("failed to read managed UVM ingress request")
                .with_detail(error.to_string())
        })?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() >= MAX_HTTP_INGRESS_REQUEST_BYTES {
            return Err(PlatformError::invalid(
                "managed UVM ingress request exceeded maximum header size",
            ));
        }
    }
    String::from_utf8(request).map_err(|error| {
        PlatformError::invalid("managed UVM ingress request was not valid UTF-8")
            .with_detail(error.to_string())
    })
}

fn build_http_ingress_response(request: &str, web_root: &Path) -> String {
    let Some((method, request_path)) = parse_http_request_line(request) else {
        return render_http_ingress_response(
            "400 Bad Request",
            "text/plain; charset=utf-8",
            "bad request\n",
            false,
        );
    };
    if !matches!(method, "GET" | "HEAD") {
        return render_http_ingress_response(
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            "method not allowed\n",
            method == "HEAD",
        );
    }
    let Some(relative_path) = ingress_request_target_path(request_path) else {
        return render_http_ingress_response(
            "400 Bad Request",
            "text/plain; charset=utf-8",
            "invalid path\n",
            method == "HEAD",
        );
    };
    let target = web_root.join(relative_path);
    match fs::read(&target) {
        Ok(body) => render_http_ingress_binary_response(
            "200 OK",
            ingress_content_type(&target),
            &body,
            method == "HEAD",
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => render_http_ingress_response(
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n",
            method == "HEAD",
        ),
        Err(_) => render_http_ingress_response(
            "500 Internal Server Error",
            "text/plain; charset=utf-8",
            "internal error\n",
            method == "HEAD",
        ),
    }
}

fn parse_http_request_line(request: &str) -> Option<(&str, &str)> {
    let line = request.lines().next()?.trim();
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    let _version = parts.next()?;
    Some((method, path))
}

fn ingress_request_target_path(path: &str) -> Option<PathBuf> {
    let target = path.split('?').next().unwrap_or(path);
    let trimmed = target.trim_start_matches('/');
    let normalized = if trimmed.is_empty() {
        String::from("index.html")
    } else if target.ends_with('/') {
        format!("{trimmed}index.html")
    } else {
        trimmed.to_owned()
    };
    let mut resolved = PathBuf::new();
    for segment in normalized.split('/') {
        if segment.is_empty() || matches!(segment, "." | "..") {
            return None;
        }
        resolved.push(segment);
    }
    Some(resolved)
}

fn ingress_content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|value| value.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("txt") | Some("log") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn render_http_ingress_response(
    status: &str,
    content_type: &str,
    body: &str,
    head_only: bool,
) -> String {
    render_http_ingress_binary_response(status, content_type, body.as_bytes(), head_only)
}

fn render_http_ingress_binary_response(
    status: &str,
    content_type: &str,
    body: &[u8],
    head_only: bool,
) -> String {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if !head_only {
        response.push_str(&String::from_utf8_lossy(body));
    }
    response
}

fn guest_control_network_access_summary(
    control: &SoftVmGuestControl,
    http_ingress: Option<&ManagedIngressState>,
    tcp_ingress: Option<&ManagedTcpIngressState>,
    udp_ingress: Option<&ManagedUdpIngressState>,
) -> serde_json::Value {
    let last_url = guest_control_file(control, "/run/guest-egress/last-url")
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let last_tcp_target = guest_control_file(control, "/run/guest-tcp/last-target")
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let last_udp_target = guest_control_file(control, "/run/guest-udp/last-target")
        .map(str::trim)
        .filter(|value| !value.is_empty());
    serde_json::json!({
        "network_mode": SOFTWARE_DBT_NETWORK_MODE,
        "internet_nat": true,
        "ssh_available": false,
        "guest_exec_route_available": false,
        "egress_transport": SOFTWARE_DBT_EGRESS_TRANSPORT,
        "ingress_transport": SOFTWARE_DBT_INGRESS_TRANSPORT,
        "ingress_http_ready": http_ingress.map(|state| state.ready).unwrap_or(false),
        "ingress_http_bind": http_ingress.map(|state| state.http_bind.clone()),
        "ingress_http_url": http_ingress.map(|state| state.http_url.clone()),
        "ingress_tcp_ready": tcp_ingress.map(|state| state.ready).unwrap_or(false),
        "ingress_tcp_bind": tcp_ingress.map(|state| state.tcp_bind.clone()),
        "ingress_tcp_service": tcp_ingress.map(|state| state.service_name.clone()),
        "ingress_udp_ready": udp_ingress.map(|state| state.ready).unwrap_or(false),
        "ingress_udp_bind": udp_ingress.map(|state| state.udp_bind.clone()),
        "ingress_udp_service": udp_ingress.map(|state| state.service_name.clone()),
        "guest_web_root": SOFTWARE_DBT_GUEST_WEB_ROOT,
        "supported_guest_commands": [
            "ip addr",
            "ip route",
            "hostname -I",
            "resolvectl status",
            "nslookup <hostname>",
            "getent hosts <hostname>",
            "curl <http-or-https-url>",
            "curl -I <http-or-https-url>",
            "fetch <http-or-https-url>",
            "nc <host> <port>",
            "nc -z <host> <port>",
            "nc <host> <port> <payload>",
            "nc -u <host> <port>",
            "nc -zu <host> <port>",
            "nc -u <host> <port> <payload>",
        ],
        "last_response": last_url.map(|url| {
            serde_json::json!({
                "url": url,
                "method": guest_control_file(control, "/run/guest-egress/last-method").map(str::trim).filter(|value| !value.is_empty()),
                "status_line": guest_control_file(control, "/run/guest-egress/last-status-line").map(str::trim).filter(|value| !value.is_empty()),
                "content_type": guest_control_file(control, "/run/guest-egress/last-content-type").map(str::trim).filter(|value| !value.is_empty()),
                "body_bytes": guest_control_file(control, "/run/guest-egress/last-body-bytes").map(str::trim).and_then(|value| value.parse::<u64>().ok()),
                "truncated": guest_control_file(control, "/run/guest-egress/last-truncated").map(str::trim).map(|value| value == "true"),
            })
        }),
        "last_tcp_exchange": last_tcp_target.map(|target| {
            serde_json::json!({
                "target": target,
                "probe_only": guest_control_file(control, "/run/guest-tcp/last-probe").map(str::trim).map(|value| value == "true"),
                "bytes_sent": guest_control_file(control, "/run/guest-tcp/last-bytes-sent").map(str::trim).and_then(|value| value.parse::<u64>().ok()),
                "bytes_received": guest_control_file(control, "/run/guest-tcp/last-bytes-received").map(str::trim).and_then(|value| value.parse::<u64>().ok()),
            })
        }),
        "last_udp_exchange": last_udp_target.map(|target| {
            serde_json::json!({
                "target": target,
                "probe_only": guest_control_file(control, "/run/guest-udp/last-probe").map(str::trim).map(|value| value == "true"),
                "bytes_sent": guest_control_file(control, "/run/guest-udp/last-bytes-sent").map(str::trim).and_then(|value| value.parse::<u64>().ok()),
                "bytes_received": guest_control_file(control, "/run/guest-udp/last-bytes-received").map(str::trim).and_then(|value| value.parse::<u64>().ok()),
            })
        }),
    })
}

fn augmented_worker_manifest(
    worker_manifest: &RunnerWorkerManifestState,
    network_access: &serde_json::Value,
) -> Result<RunnerWorkerManifestState> {
    let workers = worker_manifest
        .workers
        .iter()
        .map(|worker| augment_worker_with_network_access(worker, network_access))
        .collect::<Vec<_>>();
    let manifest_fingerprint =
        build_worker_manifest_fingerprint(&workers, worker_manifest.guest_control_ready)?;
    Ok(RunnerWorkerManifestState {
        workers,
        guest_control_ready: worker_manifest.guest_control_ready,
        manifest_version: worker_manifest.manifest_version,
        manifest_fingerprint,
    })
}

fn augment_worker_with_network_access(
    worker: &serde_json::Value,
    network_access: &serde_json::Value,
) -> serde_json::Value {
    let mut worker = worker.clone();
    if worker.get("name").and_then(serde_json::Value::as_str) != Some("net") {
        return worker;
    }
    let Some(detail) = worker
        .get_mut("detail")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return worker;
    };
    detail.insert(
        String::from("network_mode"),
        network_access["network_mode"].clone(),
    );
    detail.insert(
        String::from("internet_nat"),
        network_access["internet_nat"].clone(),
    );
    detail.insert(
        String::from("ssh_available"),
        network_access["ssh_available"].clone(),
    );
    detail.insert(
        String::from("guest_exec_route_available"),
        network_access["guest_exec_route_available"].clone(),
    );
    detail.insert(
        String::from("egress_transport"),
        network_access["egress_transport"].clone(),
    );
    detail.insert(
        String::from("ingress_transport"),
        network_access["ingress_transport"].clone(),
    );
    detail.insert(
        String::from("ingress_http_ready"),
        network_access["ingress_http_ready"].clone(),
    );
    detail.insert(
        String::from("ingress_tcp_ready"),
        network_access["ingress_tcp_ready"].clone(),
    );
    detail.insert(
        String::from("ingress_udp_ready"),
        network_access["ingress_udp_ready"].clone(),
    );
    detail.insert(
        String::from("ingress_http_bind"),
        network_access["ingress_http_bind"].clone(),
    );
    detail.insert(
        String::from("ingress_http_url"),
        network_access["ingress_http_url"].clone(),
    );
    detail.insert(
        String::from("ingress_tcp_bind"),
        network_access["ingress_tcp_bind"].clone(),
    );
    detail.insert(
        String::from("ingress_tcp_service"),
        network_access["ingress_tcp_service"].clone(),
    );
    detail.insert(
        String::from("ingress_udp_bind"),
        network_access["ingress_udp_bind"].clone(),
    );
    detail.insert(
        String::from("ingress_udp_service"),
        network_access["ingress_udp_service"].clone(),
    );
    worker
}

fn execute_with_runner_contract(
    config: RunnerConfig,
    runner_contract: RunnerExecutionContract,
) -> Result<serde_json::Value> {
    run_supervisor_worker(&runner_contract, |_worker_contract| {
        let localized_artifacts = run_block_worker(&runner_contract, &config)?;
        if config.probe_mode.as_deref() == Some("qemu_tcg") {
            return qemu_tcg_probe_output(&runner_contract, &config, localized_artifacts);
        }
        let mut runtime = run_core_worker(&runner_contract, &config, localized_artifacts)?;
        let guest_control = runtime.instance.guest_control()?;
        let heartbeat = runtime.instance.heartbeat();
        let completed_events = runtime
            .instance
            .execution
            .completed_events
            .iter()
            .map(|event| {
                serde_json::json!({
                    "kind": event.kind,
                    "detail": event.detail,
                })
            })
            .collect::<Vec<_>>();
        let instruction_trace = runtime
            .instance
            .execution
            .instruction_trace
            .iter()
            .map(|trace| {
                serde_json::json!({
                    "program_name": trace.program_name,
                    "guest_address": trace.guest_address,
                    "opcode": trace.opcode,
                    "detail": trace.detail,
                })
            })
            .collect::<Vec<_>>();
        let resident_programs = runtime
            .instance
            .execution
            .resident_programs
            .iter()
            .map(|program| {
                serde_json::json!({
                    "name": program.name,
                    "mapped_region": program.mapped_region,
                    "entry_point": program.entry_point,
                    "byte_len": program.bytecode.len(),
                    "content_fingerprint": program.content_fingerprint,
                })
            })
            .collect::<Vec<_>>();
        let guest_memory_allocations = runtime
            .instance
            .execution
            .guest_ram_allocations
            .iter()
            .map(|allocation| {
                serde_json::json!({
                    "label": allocation.label,
                    "mapped_region": allocation.mapped_region,
                    "guest_address": allocation.guest_address,
                    "byte_len": allocation.byte_len,
                })
            })
            .collect::<Vec<_>>();
        let mmio_regions = runtime
            .instance
            .execution
            .mmio_regions
            .iter()
            .map(|region| {
                serde_json::json!({
                    "name": region.name,
                    "guest_physical_base": region.guest_physical_base,
                    "byte_len": region.byte_len,
                    "read_dispatch": region.read_dispatch,
                    "write_dispatch": region.write_dispatch,
                })
            })
            .collect::<Vec<_>>();
        let pending_interrupts = runtime
            .instance
            .execution
            .pending_interrupts
            .iter()
            .map(|interrupt| {
                serde_json::json!({
                    "vector": interrupt.vector,
                    "source": interrupt.source,
                    "detail": interrupt.detail,
                })
            })
            .collect::<Vec<_>>();
        let mmio_access_log = runtime
            .instance
            .execution
            .mmio_access_log
            .iter()
            .map(|access| {
                serde_json::json!({
                    "region_name": access.region_name,
                    "access_kind": access.access_kind,
                    "guest_physical_address": access.guest_physical_address,
                    "value": access.value,
                    "detail": access.detail,
                })
            })
            .collect::<Vec<_>>();
        let virtual_file_residency = guest_control
            .files
            .iter()
            .map(|file| {
                serde_json::json!({
                    "path": file.path,
                    "resident_guest_address": file.resident_guest_address,
                    "resident_byte_len": file.resident_byte_len,
                    "content_fingerprint": file.content_fingerprint,
                })
            })
            .collect::<Vec<_>>();
        let command_channels = guest_control
            .channels
            .iter()
            .map(|channel| {
                serde_json::json!({
                    "name": channel.name,
                    "delivery_path": channel.delivery_path,
                    "state": channel.state,
                    "tx_count": channel.tx_count,
                    "rx_count": channel.rx_count,
                    "last_command": channel.last_command,
                    "last_exit_code": channel.last_exit_code,
                })
            })
            .collect::<Vec<_>>();
        let worker_manifest = build_worker_manifest_state(
            &runner_contract,
            &config,
            runtime.instance.phase,
            heartbeat.guest_memory_bytes,
            &runtime.instance,
            &runtime.boot_witness,
        )?;
        let secure_boot_measurements = runtime.boot_witness.secure_boot_measurements.clone();
        let boot_stages = runtime.boot_witness.stages.clone();
        let console_trace = runtime.boot_witness.console_trace.clone();
        let worker_states = runner_contract.worker_states(runtime.instance.phase);

        Ok(serde_json::json!({
            "session_id": config.session_id,
            "instance_id": config.instance_id,
            "backend": HypervisorBackend::SoftwareDbt.as_str(),
            "phase": heartbeat.phase,
            "heartbeat_sequence": heartbeat.sequence,
            "guest_memory_bytes": heartbeat.guest_memory_bytes,
            "vcpu": heartbeat.vcpu,
            "machine_family": runtime.instance.spec.machine.machine_family,
            "guest_architecture": runtime.instance.spec.machine.guest_architecture,
            "boot_path": runtime.instance.spec.machine.boot_path,
            "device_model": runtime.instance.spec.machine.device_model,
            "boot_medium": runtime.instance.spec.machine.boot.medium,
            "firmware_profile": config.firmware_profile,
            "primary_boot_device": runtime.instance.spec.machine.boot.primary_boot_device,
            "disk_image": config.disk_image,
            "cdrom_image": config.cdrom_image,
            "memory_backing": config.memory_backing.as_str(),
            "execution_class": runtime.instance.spec.execution_class,
            "restart_policy": config.restart_policy,
            "migration_kind": config.migration_kind,
            "secure_boot": config.require_secure_boot,
            "secure_boot_measurements": secure_boot_measurements,
            "sandbox_layers": runner_contract.sandbox_layers.clone(),
            "sandbox_enforcement_mode": RUNNER_SANDBOX_ENFORCEMENT_MODE,
            "sandbox_contract_source": RUNNER_SANDBOX_CONTRACT_SOURCE,
            "worker_states": worker_states,
            "worker_manifest_version": worker_manifest.manifest_version,
            "worker_manifest_fingerprint": worker_manifest.manifest_fingerprint,
            "workers": worker_manifest.workers,
            "boot_stages": boot_stages,
            "console_trace": console_trace,
            "guest_control_ready": worker_manifest.guest_control_ready,
            "guest_control": {
                "hostname": guest_control.hostname,
                "ready_marker_path": guest_control.ready_marker_path,
                "cwd": guest_control.cwd,
                "history_len": guest_control.history.len(),
                "benchmark_runs": guest_control.benchmark_runs,
                "guest_memory_backed": true,
                "command_channels": command_channels,
                "compatibility_projection": {
                    "mode": "legacy_file_projection",
                    "file_count": guest_control.files.len(),
                },
                "access": guest_control_network_access_summary(&guest_control, None, None, None),
                "virtual_files": guest_control
                    .files
                    .iter()
                    .map(|file| file.path.clone())
                    .collect::<Vec<_>>(),
                "virtual_file_residency": virtual_file_residency,
                "service_states": guest_control
                    .services
                    .iter()
                    .map(|service| serde_json::json!({
                        "name": service.name,
                        "state": service.state,
                    }))
                    .collect::<Vec<_>>(),
                "commands": runtime
                    .guest_command_results
                    .iter()
                    .map(|result| serde_json::json!({
                        "channel": result.channel,
                        "command": result.command,
                        "exit_code": result.exit_code,
                        "execution_semantics": result.execution_semantics,
                        "instruction_count": result.instruction_count,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                    }))
                    .collect::<Vec<_>>(),
            },
            "native_execution": {
                "execution_semantics": "interpreted_guest_isa_v0",
                "guest_memory_backed": true,
                "reset_vector": runtime.instance.execution.reset_vector,
                "steps_executed": runtime.instance.execution.steps_executed,
                "instruction_pointer": runtime.instance.execution.cpu_state.instruction_pointer,
                "stack_pointer": runtime.instance.execution.cpu_state.stack_pointer,
                "interrupts_enabled": runtime.instance.execution.cpu_state.interrupts_enabled,
                "zero_flag": runtime.instance.execution.cpu_state.zero_flag,
                "sign_flag": runtime.instance.execution.cpu_state.sign_flag,
                "carry_flag": runtime.instance.execution.cpu_state.carry_flag,
                "last_trap_vector": runtime.instance.execution.cpu_state.last_trap_vector,
                "last_trap_detail": runtime.instance.execution.cpu_state.last_trap_detail,
                "trap_frame_depth": runtime.instance.execution.cpu_state.trap_frame_depth,
                "faulted": runtime.instance.execution.cpu_state.faulted,
                "fault_vector": runtime.instance.execution.cpu_state.fault_vector,
                "fault_detail": runtime.instance.execution.cpu_state.fault_detail,
                "call_depth": runtime.instance.execution.cpu_state.call_depth,
                "halted": runtime.instance.execution.cpu_state.halted,
                "artifact_count": runtime.instance.execution.boot_artifacts.len(),
                "resident_program_count": runtime.instance.execution.resident_programs.len(),
                "resident_programs": resident_programs,
                "mmio_regions": mmio_regions,
                "mmio_access_log": mmio_access_log,
                "pending_interrupts": pending_interrupts,
                "guest_memory_resident_bytes": runtime.instance.execution.guest_memory_bytes.len(),
                "guest_memory_allocation_count": runtime.instance.execution.guest_ram_allocations.len(),
                "guest_memory_allocations": guest_memory_allocations,
                "completed_events": completed_events,
                "instruction_trace": instruction_trace,
            },
            "telemetry": config.telemetry,
            "numa_nodes": config.numa_nodes,
        }))
    })
}

fn execute(config: RunnerConfig, backend_env: Option<String>) -> Result<serde_json::Value> {
    validate_backend_env(backend_env)?;
    validate_full_vm_contract(&config)?;
    let runner_contract = RunnerExecutionContract::from_process_env()?;
    execute_with_runner_contract(config, runner_contract)
}

fn execute_supervise_with_emitter_and_control<F>(
    config: RunnerConfig,
    backend_env: Option<String>,
    control_rx: Option<mpsc::Receiver<String>>,
    mut emit: F,
) -> Result<()>
where
    F: FnMut(serde_json::Value) -> Result<()>,
{
    validate_backend_env(backend_env)?;
    validate_full_vm_contract(&config)?;
    validate_supervise_contract(&config)?;
    let session_id = config.session_id.clone();
    let instance_id = config.instance_id.clone();
    let stop_sentinel = config.stop_sentinel.clone();
    let heartbeat_interval_ms = config.heartbeat_interval_ms;
    let max_heartbeats = config.max_heartbeats;
    let runner_contract = RunnerExecutionContract::from_process_env()?;
    run_supervisor_worker(&runner_contract, |_worker_contract| {
        let localized_artifacts = run_block_worker(&runner_contract, &config)?;
        let core_worker =
            spawn_supervised_core_worker(&runner_contract, &config, localized_artifacts)?;
        let started = core_worker.receive_started()?;
        let mut http_ingress = Some(ManagedHttpIngress::start(
            &session_id,
            config
                .ingress_http_bind
                .as_deref()
                .unwrap_or(SOFTWARE_DBT_DEFAULT_INGRESS_HTTP_BIND),
            &started.guest_control,
        )?);
        let mut tcp_ingress = Some(ManagedTcpIngress::start(
            config
                .ingress_tcp_bind
                .as_deref()
                .unwrap_or(SOFTWARE_DBT_DEFAULT_INGRESS_TCP_BIND),
            &started.guest_control,
        )?);
        let mut udp_ingress = Some(ManagedUdpIngress::start(
            config
                .ingress_udp_bind
                .as_deref()
                .unwrap_or(SOFTWARE_DBT_DEFAULT_INGRESS_UDP_BIND),
            &started.guest_control,
        )?);
        if let Some(ingress) = http_ingress.as_ref() {
            ingress.sync(&started.guest_control)?;
        }
        if let Some(ingress) = tcp_ingress.as_mut() {
            ingress.sync(&started.guest_control)?;
        }
        if let Some(ingress) = udp_ingress.as_mut() {
            ingress.sync(&started.guest_control)?;
        }
        let started_network_access = guest_control_network_access_summary(
            &started.guest_control,
            http_ingress.as_ref().map(ManagedHttpIngress::state),
            tcp_ingress.as_ref().map(ManagedTcpIngress::state),
            udp_ingress.as_ref().map(ManagedUdpIngress::state),
        );
        let started_worker_manifest =
            augmented_worker_manifest(&started.worker_manifest, &started_network_access)?;
        let mut current_phase = started.phase;
        let mut last_heartbeat_sequence = 0_u64;
        let mut current_worker_manifest = started_worker_manifest.clone();
        let mut current_guest_control = started.guest_control.clone();
        let started_worker_states = runner_contract.worker_states(started.phase);
        let started_secure_boot_measurements =
            started.boot_witness.secure_boot_measurements.clone();
        let started_boot_stages = started.boot_witness.stages.clone();
        let started_console_trace = started.boot_witness.console_trace.clone();

        emit(serde_json::json!({
            "event": "lifecycle",
            "state": "started",
            "session_id": &session_id,
            "instance_id": &instance_id,
            "backend": HypervisorBackend::SoftwareDbt.as_str(),
            "artifact_policy": "local_files_only",
            "execution_semantics": "interpreted_guest_isa_v0",
            "phase": started.phase.as_str(),
            "memory_backing": config.memory_backing.as_str(),
            "sandbox_layers": runner_contract.sandbox_layers.clone(),
            "sandbox_enforcement_mode": RUNNER_SANDBOX_ENFORCEMENT_MODE,
            "sandbox_contract_source": RUNNER_SANDBOX_CONTRACT_SOURCE,
            "worker_states": started_worker_states,
            "workers": started_worker_manifest.workers.clone(),
            "guest_control_ready": started_worker_manifest.guest_control_ready,
            "worker_manifest_version": started_worker_manifest.manifest_version,
            "worker_manifest_fingerprint": started_worker_manifest.manifest_fingerprint.clone(),
            "network_access": started_network_access,
            "secure_boot": config.require_secure_boot,
            "secure_boot_measurements": started_secure_boot_measurements,
            "boot_stages": started_boot_stages,
            "console_trace": started_console_trace,
            "heartbeat_interval_ms": heartbeat_interval_ms,
            "max_heartbeats": max_heartbeats,
        }))?;

        if !started.guest_command_results.is_empty() {
            emit(serde_json::json!({
                "event": "guest_commands",
                "session_id": &session_id,
                "instance_id": &instance_id,
                "results": started
                    .guest_command_results
                    .iter()
                    .map(|result| serde_json::json!({
                        "channel": result.channel,
                        "command": result.command,
                        "exit_code": result.exit_code,
                        "execution_semantics": result.execution_semantics,
                        "instruction_count": result.instruction_count,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                    }))
                    .collect::<Vec<_>>(),
            }))?;
        }

        let stop_reason = loop {
            if let Some(sentinel) = stop_sentinel.as_deref()
                && Path::new(sentinel).exists()
            {
                break String::from("stop_sentinel_detected");
            }

            if let Some(control_rx) = control_rx.as_ref() {
                match control_rx.try_recv() {
                    Ok(command) if is_stop_command(&command) => {
                        break format!("control_command:{command}");
                    }
                    Ok(_) | Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => {
                        break String::from("control_channel_disconnected");
                    }
                }
            }

            let heartbeat = core_worker.heartbeat()?;
            current_phase = heartbeat.phase;
            last_heartbeat_sequence = heartbeat.heartbeat.sequence;
            current_guest_control = heartbeat.guest_control.clone();
            if let Some(ingress) = http_ingress.as_ref() {
                ingress.sync(&heartbeat.guest_control)?;
            }
            if let Some(ingress) = tcp_ingress.as_mut() {
                ingress.sync(&heartbeat.guest_control)?;
            }
            if let Some(ingress) = udp_ingress.as_mut() {
                ingress.sync(&heartbeat.guest_control)?;
            }
            let heartbeat_network_access = guest_control_network_access_summary(
                &heartbeat.guest_control,
                http_ingress.as_ref().map(ManagedHttpIngress::state),
                tcp_ingress.as_ref().map(ManagedTcpIngress::state),
                udp_ingress.as_ref().map(ManagedUdpIngress::state),
            );
            current_worker_manifest =
                augmented_worker_manifest(&heartbeat.worker_manifest, &heartbeat_network_access)?;
            emit(serde_json::json!({
                "event": "heartbeat",
                "session_id": &session_id,
                "instance_id": &instance_id,
                "backend": heartbeat.heartbeat.backend,
                "phase": heartbeat.heartbeat.phase,
                "heartbeat_sequence": heartbeat.heartbeat.sequence,
                "guest_memory_bytes": heartbeat.heartbeat.guest_memory_bytes,
                "vcpu": heartbeat.heartbeat.vcpu,
                "worker_states": runner_contract.worker_states(current_phase),
                "workers": current_worker_manifest.workers.clone(),
                "guest_control_ready": current_worker_manifest.guest_control_ready,
                "worker_manifest_version": current_worker_manifest.manifest_version,
                "worker_manifest_fingerprint": current_worker_manifest.manifest_fingerprint.clone(),
                "network_access": heartbeat_network_access,
            }))?;

            if let Some(max_heartbeats) = max_heartbeats
                && heartbeat.heartbeat.sequence >= max_heartbeats
            {
                break String::from("max_heartbeats_reached");
            }

            if heartbeat_interval_ms > 0 {
                thread::sleep(Duration::from_millis(heartbeat_interval_ms));
            }
        };

        let stopping_network_access = guest_control_network_access_summary(
            &current_guest_control,
            http_ingress.as_ref().map(ManagedHttpIngress::state),
            tcp_ingress.as_ref().map(ManagedTcpIngress::state),
            udp_ingress.as_ref().map(ManagedUdpIngress::state),
        );
        emit(serde_json::json!({
            "event": "lifecycle",
            "state": "stopping",
            "session_id": &session_id,
            "instance_id": &instance_id,
            "reason": stop_reason,
            "final_heartbeat_sequence": last_heartbeat_sequence,
            "worker_states": runner_contract.worker_states(current_phase),
            "worker_manifest_version": current_worker_manifest.manifest_version,
            "worker_manifest_fingerprint": current_worker_manifest.manifest_fingerprint.clone(),
            "network_access": stopping_network_access,
        }))?;

        let stopped = core_worker.stop()?;
        let stopped_http_ingress_state = if let Some(ingress) = http_ingress.as_mut() {
            Some(ingress.stop()?)
        } else {
            None
        };
        let stopped_tcp_ingress_state = if let Some(ingress) = tcp_ingress.as_mut() {
            Some(ingress.stop()?)
        } else {
            None
        };
        let stopped_udp_ingress_state = if let Some(ingress) = udp_ingress.as_mut() {
            Some(ingress.stop()?)
        } else {
            None
        };
        let stopped_network_access = guest_control_network_access_summary(
            &stopped.guest_control,
            stopped_http_ingress_state.as_ref(),
            stopped_tcp_ingress_state.as_ref(),
            stopped_udp_ingress_state.as_ref(),
        );
        let stopped_worker_manifest =
            augmented_worker_manifest(&stopped.worker_manifest, &stopped_network_access)?;
        let stopped_worker_states = runner_contract.worker_states(stopped.phase);

        emit(serde_json::json!({
            "event": "lifecycle",
            "state": "stopped",
            "session_id": &session_id,
            "instance_id": &instance_id,
            "phase": stopped.phase.as_str(),
            "final_heartbeat_sequence": stopped.final_heartbeat_sequence,
            "worker_states": stopped_worker_states,
            "workers": stopped_worker_manifest.workers.clone(),
            "worker_manifest_version": stopped_worker_manifest.manifest_version,
            "worker_manifest_fingerprint": stopped_worker_manifest.manifest_fingerprint.clone(),
            "network_access": stopped_network_access,
        }))?;

        Ok(())
    })
}

fn execute_supervise_with_emitter<F>(
    config: RunnerConfig,
    backend_env: Option<String>,
    emit: F,
) -> Result<()>
where
    F: FnMut(serde_json::Value) -> Result<()>,
{
    let control_rx = config.max_heartbeats.is_none().then(spawn_control_reader);
    execute_supervise_with_emitter_and_control(config, backend_env, control_rx, emit)
}

fn execute_supervise(config: RunnerConfig, backend_env: Option<String>) -> Result<()> {
    execute_supervise_with_emitter(config, backend_env, emit_json_line)
}

fn run() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let config = RunnerConfig::parse(&args)?;
    match config.runner_mode {
        RunnerMode::OneShot => {
            let output = execute(config, env::var("UVM_BACKEND").ok())?;
            let rendered = serde_json::to_string_pretty(&output).map_err(|error| {
                PlatformError::invalid("failed to serialize runner output")
                    .with_detail(error.to_string())
            })?;
            println!("{rendered}");
        }
        RunnerMode::Supervise => execute_supervise(config, env::var("UVM_BACKEND").ok())?,
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{}", error.message);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        io::{Read, Write},
        net::{TcpStream, UdpSocket},
        path::PathBuf,
        sync::{
            atomic::{AtomicU64, Ordering},
            mpsc,
        },
        thread,
        time::Duration,
    };

    use super::{
        LocalizedExecutionArtifacts, RUNNER_WORKER_MANIFEST_VERSION, RunnerConfig,
        RunnerExecutionContract, RunnerMode, RunnerWorkerRole, SOFTWARE_DBT_EGRESS_TRANSPORT,
        SOFTWARE_DBT_GUEST_WEB_ROOT, SOFTWARE_DBT_INGRESS_TRANSPORT, SOFTWARE_DBT_NETWORK_MODE,
        SOFTWARE_DBT_SANDBOX_LAYER_ORDER, build_machine_spec, build_worker_manifest_fingerprint,
        execute, execute_supervise_with_emitter, execute_supervise_with_emitter_and_control,
        execute_with_runner_contract, qemu_tcg_probe_output_from_harness_artifacts,
        run_block_worker, spawn_supervised_core_worker,
    };

    static ARTIFACT_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn next_temp_path(name: &str, extension: &str) -> PathBuf {
        let mut path = env::temp_dir();
        let counter = ARTIFACT_COUNTER.fetch_add(1, Ordering::Relaxed);
        path.push(format!(
            "uhost_uvm_runner_{name}_{}_{}.{}",
            std::process::id(),
            counter,
            extension
        ));
        path
    }

    fn write_local_artifact(name: &str, contents: &[u8]) -> String {
        let path = next_temp_path(name, "bin");
        fs::write(&path, contents).unwrap_or_else(|error| panic!("{error}"));
        path.to_string_lossy().to_string()
    }

    fn http_get_text(url: &str) -> String {
        let authority = url
            .strip_prefix("http://")
            .unwrap_or_else(|| panic!("expected http url, got `{url}`"));
        let mut stream = TcpStream::connect(authority).unwrap_or_else(|error| panic!("{error}"));
        let request = format!("GET / HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .unwrap_or_else(|error| panic!("{error}"));
        response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_owned())
            .unwrap_or_else(|| panic!("missing http response body"))
    }

    fn tcp_exchange_text(authority: &str, payload: &str) -> String {
        let mut stream = TcpStream::connect(authority).unwrap_or_else(|error| panic!("{error}"));
        stream
            .write_all(payload.as_bytes())
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .unwrap_or_else(|error| panic!("{error}"));
        response
    }

    fn udp_exchange_text(authority: &str, payload: &str) -> String {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap_or_else(|error| panic!("{error}"));
        socket
            .send_to(payload.as_bytes(), authority)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut buffer = [0_u8; 4096];
        let (read, _) = socket
            .recv_from(&mut buffer)
            .unwrap_or_else(|error| panic!("{error}"));
        String::from_utf8_lossy(&buffer[..read]).into_owned()
    }

    fn worker_manifest_entry<'a>(
        workers: &'a [serde_json::Value],
        name: &str,
    ) -> &'a serde_json::Value {
        workers
            .iter()
            .find(|value| value["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("missing worker manifest entry `{name}`"))
    }

    fn worker_manifest_fingerprint(event: &serde_json::Value) -> &str {
        event["worker_manifest_fingerprint"]
            .as_str()
            .unwrap_or_else(|| panic!("missing worker manifest fingerprint"))
    }

    fn assert_output_worker_manifest_parity(output: &serde_json::Value) -> String {
        assert_eq!(
            output["worker_manifest_version"].as_str(),
            Some(RUNNER_WORKER_MANIFEST_VERSION)
        );
        let workers = output["workers"]
            .as_array()
            .unwrap_or_else(|| panic!("missing workers array"));
        let guest_control_ready = output["guest_control_ready"]
            .as_bool()
            .unwrap_or_else(|| panic!("missing guest_control_ready"));
        let expected_fingerprint = build_worker_manifest_fingerprint(workers, guest_control_ready)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            worker_manifest_fingerprint(output),
            expected_fingerprint.as_str()
        );
        expected_fingerprint
    }

    #[test]
    fn parser_accepts_minimal_software_backend_contract() {
        let local_disk = write_local_artifact("disk", b"software-dbt-minimal-disk");
        let local_firmware = write_local_artifact("firmware", b"software-dbt-minimal-firmware");
        let args = vec![
            String::from("--session"),
            String::from("urs_1"),
            String::from("--instance"),
            String::from("uvi_1"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--firmware-artifact"),
            local_firmware.clone(),
            String::from("--disk"),
            local_disk,
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
            String::from("--telemetry"),
            String::from("heartbeat"),
            String::from("--numa-node"),
            String::from("0"),
            String::from("--guest-command"),
            String::from("uname -a"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let output = execute(config, Some(String::from("software_dbt")))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(output["backend"].as_str(), Some("software_dbt"));
        assert_eq!(output["phase"].as_str(), Some("running"));
        assert_eq!(output["boot_medium"].as_str(), Some("firmware"));
        assert_eq!(output["primary_boot_device"].as_str(), Some("disk"));
        assert_eq!(output["memory_backing"].as_str(), Some("file_backed"));
        assert_eq!(
            output["sandbox_enforcement_mode"].as_str(),
            Some("worker_contract")
        );
        assert_eq!(
            output["sandbox_contract_source"].as_str(),
            Some("launch_contract")
        );
        assert_eq!(output["guest_control_ready"].as_bool(), Some(true));
        let worker_manifest_fingerprint = assert_output_worker_manifest_parity(&output);
        assert_eq!(output["guest_control"]["history_len"].as_u64(), Some(1));
        assert_eq!(
            output["guest_control"]["guest_memory_backed"].as_bool(),
            Some(true)
        );
        assert_eq!(
            output["guest_control"]["access"]["network_mode"].as_str(),
            Some(SOFTWARE_DBT_NETWORK_MODE)
        );
        assert_eq!(
            output["guest_control"]["access"]["internet_nat"].as_bool(),
            Some(true)
        );
        assert_eq!(
            output["guest_control"]["access"]["ssh_available"].as_bool(),
            Some(false)
        );
        assert_eq!(
            output["guest_control"]["access"]["guest_exec_route_available"].as_bool(),
            Some(false)
        );
        assert_eq!(
            output["guest_control"]["access"]["egress_transport"].as_str(),
            Some(SOFTWARE_DBT_EGRESS_TRANSPORT)
        );
        assert_eq!(
            output["guest_control"]["access"]["ingress_transport"].as_str(),
            Some(SOFTWARE_DBT_INGRESS_TRANSPORT)
        );
        assert_eq!(
            output["guest_control"]["access"]["ingress_http_ready"].as_bool(),
            Some(false)
        );
        assert_eq!(
            output["guest_control"]["access"]["ingress_tcp_ready"].as_bool(),
            Some(false)
        );
        assert_eq!(
            output["guest_control"]["access"]["guest_web_root"].as_str(),
            Some(SOFTWARE_DBT_GUEST_WEB_ROOT)
        );
        assert!(output["boot_stages"].as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .any(|stage| stage == "firmware:dispatch_complete")
        }));
        assert!(output["console_trace"].as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .any(|line| line.contains("native executor reached guest control handoff"))
        }));
        assert_eq!(
            output["native_execution"]["execution_semantics"].as_str(),
            Some("interpreted_guest_isa_v0")
        );
        assert_eq!(
            output["native_execution"]["guest_memory_backed"].as_bool(),
            Some(true)
        );
        assert_eq!(
            output["native_execution"]["steps_executed"].as_u64(),
            Some(21)
        );
        assert_eq!(output["native_execution"]["halted"].as_bool(), Some(true));
        assert_eq!(output["native_execution"]["call_depth"].as_u64(), Some(0));
        assert!(
            output["native_execution"]["stack_pointer"]
                .as_u64()
                .is_some()
        );
        assert_eq!(
            output["native_execution"]["interrupts_enabled"].as_bool(),
            Some(true)
        );
        assert_eq!(
            output["native_execution"]["last_trap_vector"].as_u64(),
            Some(32)
        );
        assert!(
            output["native_execution"]["last_trap_detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("guest program"))
        );
        assert_eq!(
            output["native_execution"]["trap_frame_depth"].as_u64(),
            Some(0)
        );
        assert_eq!(output["native_execution"]["faulted"].as_bool(), Some(false));
        assert!(output["native_execution"]["fault_vector"].is_null());
        assert!(output["native_execution"]["fault_detail"].is_null());
        assert!(
            output["native_execution"]["mmio_regions"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .any(|value| value["name"].as_str() == Some("uart_console")))
        );
        assert!(
            output["native_execution"]["pending_interrupts"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .any(|value| value["source"].as_str() == Some("virt_timer")))
        );
        assert!(
            output["native_execution"]["mmio_access_log"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .any(|value| value["region_name"].as_str() == Some("virt_block_control")))
        );

        assert!(
            output["guest_control"]["commands"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(|value| value.get("stdout"))
                    .filter_map(serde_json::Value::as_str)
                    .any(|stdout| stdout.contains("Linux uvm-native-")))
        );
        assert!(
            output["guest_control"]["commands"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(|value| value.get("channel"))
                    .filter_map(serde_json::Value::as_str)
                    .all(|channel| channel == "serial"))
        );
        assert!(
            output["guest_control"]["commands"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(|value| value.get("execution_semantics"))
                    .filter_map(serde_json::Value::as_str)
                    .all(|value| value == "interpreted_guest_isa_v0"))
        );
        assert_eq!(
            output["guest_control"]["compatibility_projection"]["mode"].as_str(),
            Some("legacy_file_projection")
        );
        assert!(
            output["guest_control"]["command_channels"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| {
                    value["name"].as_str() == Some("serial")
                        && value["tx_count"].as_u64() == Some(1)
                        && value["rx_count"].as_u64() == Some(1)
                }))
        );
        assert!(
            output["guest_control"]["virtual_files"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .any(|path| path == "/var/log/boot.log"))
        );
        assert!(
            output["guest_control"]["virtual_file_residency"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value["path"].as_str()
                    == Some("/var/log/boot.log")
                    && value["resident_byte_len"]
                        .as_u64()
                        .is_some_and(|len| len > 0)))
        );
        assert!(
            output["native_execution"]["resident_programs"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .any(|value| value["name"].as_str() == Some("boot_dispatch")))
        );
        assert!(
            output["native_execution"]["instruction_trace"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(|value| value.get("opcode"))
                    .filter_map(serde_json::Value::as_str)
                    .any(|opcode| opcode == "guest_uname"))
        );
        assert!(
            output["native_execution"]["instruction_trace"]
                .as_array()
                .is_some_and(
                    |values| values.iter().any(|value| value["program_name"].as_str()
                        == Some("guest_kernel_service")
                        && value["opcode"].as_str() == Some("guest_service_route_dispatch"))
                )
        );
        assert!(output["sandbox_layers"].as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|value| value == "seccomp")
        }));
        assert!(output["worker_states"].as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|value| value == "supervisor:running")
                && values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .any(|value| value == "block:running")
        }));
        assert!(output["workers"].as_array().is_some_and(|values| {
            values.iter().any(|value| {
                value["name"].as_str() == Some("net")
                    && value["sandbox_enforcement_mode"].as_str() == Some("worker_contract")
                    && value["sandbox_contract_source"].as_str() == Some("launch_contract")
                    && value["execution_scope"].as_str() == Some("virtio_net_observation")
                    && value["detail"]["virtio_net_mmio_present"].as_bool() == Some(true)
                    && value["detail"]["guest_control_ready"].as_bool() == Some(true)
            }) && values.iter().any(|value| {
                value["name"].as_str() == Some("supervisor")
                    && value["detail"]["runner_mode"].as_str() == Some("one_shot")
                    && value["detail"]["core_control_path"].as_str() == Some("direct_call")
            }) && values.iter().any(|value| {
                value["name"].as_str() == Some("core")
                    && value["detail"]["instance_ownership"].as_str() == Some("call_scoped")
            }) && values.iter().any(|value| {
                value["name"].as_str() == Some("block")
                    && value["detail"]["artifact_count"].as_u64() == Some(2)
            })
        }));
        assert!(!worker_manifest_fingerprint.is_empty());
    }

    #[test]
    fn runner_executes_secure_boot_contract_and_reports_measurements() {
        let local_disk = write_local_artifact("secure_disk", b"software-dbt-secure-disk");
        let args = vec![
            String::from("--session"),
            String::from("urs_secure_1"),
            String::from("--instance"),
            String::from("uvi_secure_1"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_secure"),
            String::from("--disk"),
            local_disk,
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
            String::from("--secure-boot"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let output = execute(config, Some(String::from("software_dbt")))
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(output["secure_boot"].as_bool(), Some(true));
        assert!(
            output["secure_boot_measurements"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .any(|value| value.starts_with("firmware:sha256:")))
        );
        assert!(
            output["secure_boot_measurements"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .any(|value| value.starts_with("primary_disk:sha256:")))
        );
        assert!(output["boot_stages"].as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|stage| stage == "secure_boot:policy_enforced")
        }));
        assert!(output["console_trace"].as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|line| line.contains("Software secure boot policy enforced"))
        }));
        assert!(
            output["guest_control"]["virtual_files"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .any(|path| path == "/run/uhost/secure-boot/state"))
        );
    }

    #[test]
    fn runner_rejects_secure_boot_without_uefi_secure_firmware() {
        let local_disk = write_local_artifact("insecure_disk", b"software-dbt-insecure-disk");
        let args = vec![
            String::from("--session"),
            String::from("urs_secure_reject_1"),
            String::from("--instance"),
            String::from("uvi_secure_reject_1"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--disk"),
            local_disk,
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
            String::from("--secure-boot"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let error = execute(config, Some(String::from("software_dbt")))
            .err()
            .unwrap_or_else(|| panic!("expected secure-boot firmware rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert_eq!(
            error.message,
            "software runner secure boot requires firmware=uefi_secure"
        );
    }

    #[test]
    fn runner_execution_contract_rejects_incomplete_worker_manifest() {
        let error = RunnerExecutionContract::from_values(
            Some("capability_drop,cgroup_v2,namespaces,seccomp"),
            Some("supervisor,core,net"),
        )
        .err()
        .unwrap_or_else(|| panic!("expected worker contract rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[test]
    fn runner_execution_contract_rejects_out_of_order_sandbox_layers() {
        let error = RunnerExecutionContract::from_values(
            Some("seccomp,namespaces,cgroup_v2,capability_drop"),
            Some("supervisor,core,block,net"),
        )
        .err()
        .unwrap_or_else(|| panic!("expected sandbox layer order rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert!(error.message.contains(
            "UVM_SANDBOX_LAYERS must define `capability_drop,cgroup_v2,namespaces,seccomp` in order"
        ));
    }

    #[test]
    fn qemu_probe_mode_enforces_block_worker_contract() {
        let local_disk = write_local_artifact("probe_disk", b"software-dbt-probe-disk");
        let local_cdrom = write_local_artifact("probe_cdrom", b"software-dbt-probe-cdrom");
        let args = vec![
            String::from("--session"),
            String::from("urs_probe_contract_1"),
            String::from("--instance"),
            String::from("uvi_probe_contract_1"),
            String::from("--probe-mode"),
            String::from("qemu_tcg"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("bios"),
            String::from("--disk"),
            local_disk,
            String::from("--cdrom"),
            local_cdrom,
            String::from("--boot-device"),
            String::from("cdrom"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let runner_contract = RunnerExecutionContract {
            sandbox_layers: SOFTWARE_DBT_SANDBOX_LAYER_ORDER
                .iter()
                .map(|layer| String::from(layer.as_str()))
                .collect(),
            workers: vec![
                RunnerWorkerRole::Supervisor,
                RunnerWorkerRole::Core,
                RunnerWorkerRole::Net,
            ],
        };

        let error = execute_with_runner_contract(config, runner_contract)
            .err()
            .unwrap_or_else(|| panic!("expected block worker contract rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert_eq!(error.message, "runner worker contract is missing `block`");
    }

    #[test]
    fn qemu_probe_harness_translation_emits_worker_manifest_and_conformance() {
        let local_disk = write_local_artifact("probe_harness_disk", b"software-dbt-harness-disk");
        let local_cdrom =
            write_local_artifact("probe_harness_cdrom", b"software-dbt-harness-cdrom");
        let args = vec![
            String::from("--session"),
            String::from("urs_probe_harness_1"),
            String::from("--instance"),
            String::from("uvi_probe_harness_1"),
            String::from("--probe-mode"),
            String::from("qemu_tcg"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("bios"),
            String::from("--disk"),
            local_disk.clone(),
            String::from("--cdrom"),
            local_cdrom.clone(),
            String::from("--boot-device"),
            String::from("cdrom"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let machine = build_machine_spec(
            &config,
            LocalizedExecutionArtifacts {
                disk_image: local_disk,
                cdrom_image: Some(local_cdrom),
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let runner_contract = RunnerExecutionContract::from_values(None, None)
            .unwrap_or_else(|error| panic!("{error}"));

        let output = qemu_tcg_probe_output_from_harness_artifacts(
            &runner_contract,
            &config,
            &machine,
            serde_json::json!({
                "boot_menu_detected": true,
                "bios_installer_strings_detected": true,
                "kernel_boot_text_detected": true,
                "kernel_installer_progress_detected": true,
                "casper_cdrom_mismatch_detected": false,
                "kernel_panic_detected": false,
                "userspace_targets_detected": true,
                "serial_login_prompt_detected": true,
                "raw_log": "docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.raw.log",
                "text_log": "docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.log",
                "kernel_log": "docs/benchmarks/generated/qemu-tcg-kernel-ubuntu-26.04-probe.log",
            }),
            "SeaBIOS\nGNU GRUB\nTry or Install Ubuntu\n",
            "Linux version 7.0.0\nReached target getty.target - Login Prompts.\nlogin:\nreboot: Restarting system\nreboot: Power down\n",
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(output["probe_backend"].as_str(), Some("qemu-tcg-x86_64"));
        assert_eq!(output["probe_evidence_mode"].as_str(), Some("harness_logs"));
        assert_eq!(output["guest_control_ready"].as_bool(), Some(true));
        assert_output_worker_manifest_parity(&output);
        assert!(output["power_events"].as_array().is_some_and(|values| {
            values.iter().any(|value| value.as_str() == Some("reboot"))
                && values
                    .iter()
                    .any(|value| value.as_str() == Some("poweroff"))
        }));
        assert_eq!(
            output["qemu_tcg_conformance"]["engine"].as_str(),
            Some("qemu")
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["measurement_mode"].as_str(),
            Some("hybrid")
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["ingestion_path"].as_str(),
            Some("generated_validation_artifacts")
        );
        assert!(
            output["qemu_tcg_conformance"]["ready_scenarios"]
                .as_array()
                .is_some_and(|values| {
                    values
                        .iter()
                        .any(|value| value.as_str() == Some("cold_boot"))
                        && values
                            .iter()
                            .any(|value| value.as_str() == Some("service_readiness"))
                        && values
                            .iter()
                            .any(|value| value.as_str() == Some("fault_recovery"))
                })
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["coverage"]["install_media_boot"].as_bool(),
            Some(true)
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["coverage"]["observe_side_ready"].as_bool(),
            Some(true)
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["generated_validation_projection"]["bundle"].as_str(),
            Some("runner_qemu_tcg_conformance")
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["generated_validation_projection"]["target"].as_str(),
            Some("ubuntu_22_04_vm")
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["generated_validation_projection"]["workload_class"]
                .as_str(),
            Some("generated_validation_ubuntu_22_04_vm")
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["generated_validation_projection"]["guest_run_lineage"]
                .as_str(),
            Some("runner_qemu_tcg_conformance_ubuntu_22_04_vm")
        );
        assert!(
            output["qemu_tcg_conformance"]["generated_validation_projection"]["reference_hints"]
                .as_array()
                .is_some_and(|values| {
                    values.iter().any(|value| {
                        value.as_str()
                            == Some(
                                "docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.log",
                            )
                    }) && values.iter().any(|value| {
                        value.as_str()
                            == Some(
                                "docs/benchmarks/generated/qemu-tcg-kernel-ubuntu-26.04-probe.log",
                            )
                    })
                })
        );
        assert!(
            output["qemu_tcg_conformance"]["generated_validation_projection"]["scenario_rows"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| {
                    value["scenario"].as_str() == Some("fault_recovery")
                        && value["source_engine"].as_str() == Some("qemu")
                        && value["observe_engine"].as_str() == Some("qemu")
                        && value["backend"].as_str() == Some("qemu-tcg-x86_64")
                        && value["measurement_mode"].as_str() == Some("hybrid")
                }))
        );
        assert!(
            output["workers"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| {
                    value["name"].as_str() == Some("core")
                        && value["state"].as_str() == Some("running")
                }) && values.iter().any(|value| {
                    value["name"].as_str() == Some("net")
                        && value["detail"]["guest_control_ready"].as_bool() == Some(true)
                }))
        );
    }

    #[test]
    fn qemu_probe_mode_models_disk_boot_power_cycle_conformance() {
        let local_disk = write_local_artifact("probe_disk_boot", b"software-dbt-probe-disk-boot");
        let local_firmware =
            write_local_artifact("probe_disk_boot_firmware", b"software-dbt-probe-firmware");
        let args = vec![
            String::from("--session"),
            String::from("urs_probe_disk_boot_1"),
            String::from("--instance"),
            String::from("uvi_probe_disk_boot_1"),
            String::from("--probe-mode"),
            String::from("qemu_tcg"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--firmware-artifact"),
            local_firmware,
            String::from("--disk"),
            local_disk,
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let output = execute(config, Some(String::from("software_dbt")))
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(output["probe_backend"].as_str(), Some("qemu-tcg-x86_64"));
        assert_eq!(
            output["probe_evidence_mode"].as_str(),
            Some("modeled_softvm")
        );
        assert_eq!(output["primary_boot_device"].as_str(), Some("disk"));
        assert_eq!(output["guest_control_ready"].as_bool(), Some(true));
        assert_output_worker_manifest_parity(&output);
        assert!(output["boot_stages"].as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|stage| stage == "primary_disk:handoff_complete")
                && values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .any(|stage| stage == "probe:qemu_tcg:modeled")
        }));
        assert!(output["power_events"].as_array().is_some_and(|values| {
            values.iter().any(|value| value.as_str() == Some("reboot"))
                && values
                    .iter()
                    .any(|value| value.as_str() == Some("poweroff"))
        }));
        assert_eq!(
            output["qemu_tcg_conformance"]["measurement_mode"].as_str(),
            Some("modeled")
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["ingestion_path"].as_str(),
            Some("generated_validation_artifacts")
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["coverage"]["disk_boot"].as_bool(),
            Some(true)
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["coverage"]["aarch64"].as_bool(),
            Some(false)
        );
        assert!(
            output["qemu_tcg_conformance"]["ready_scenarios"]
                .as_array()
                .is_some_and(|values| {
                    values
                        .iter()
                        .any(|value| value.as_str() == Some("fault_recovery"))
                })
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["generated_validation_projection"]["target"].as_str(),
            Some("ubuntu_22_04_vm")
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["generated_validation_projection"]["measurement_mode"]
                .as_str(),
            Some("modeled")
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["generated_validation_projection"]["notes"]
                ["probe_evidence_mode"]
                .as_str(),
            Some("modeled_softvm")
        );
        assert!(
            output["qemu_tcg_conformance"]["generated_validation_projection"]["scenario_rows"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| {
                    value["scenario"].as_str() == Some("service_readiness")
                        && value["backend"].as_str() == Some("qemu-tcg-x86_64")
                }))
        );
    }

    #[test]
    fn qemu_probe_mode_accepts_aarch64_apple_vm_conformance_lane() {
        let local_disk = write_local_artifact("probe_aarch64_disk", b"software-dbt-aarch64-disk");
        let local_firmware =
            write_local_artifact("probe_aarch64_firmware", b"software-dbt-aarch64-firmware");
        let args = vec![
            String::from("--session"),
            String::from("urs_probe_aarch64_1"),
            String::from("--instance"),
            String::from("uvi_probe_aarch64_1"),
            String::from("--probe-mode"),
            String::from("qemu_tcg"),
            String::from("--arch"),
            String::from("aarch64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--firmware-artifact"),
            local_firmware,
            String::from("--disk"),
            local_disk,
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("apple_vm"),
            String::from("--device-model"),
            String::from("apple_integrated"),
            String::from("--machine-family"),
            String::from("aarch64_virt"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let output = execute(config, Some(String::from("software_dbt")))
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(output["guest_architecture"].as_str(), Some("aarch64"));
        assert_eq!(output["boot_path"].as_str(), Some("apple_vm"));
        assert_eq!(output["device_model"].as_str(), Some("apple_integrated"));
        assert_eq!(output["machine_family"].as_str(), Some("aarch64_virt"));
        assert_eq!(output["probe_backend"].as_str(), Some("qemu-tcg-aarch64"));
        assert_eq!(
            output["probe_evidence_mode"].as_str(),
            Some("modeled_softvm")
        );
        assert_output_worker_manifest_parity(&output);
        assert!(output["boot_stages"].as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|stage| stage == "native_executor:aarch64:ready")
        }));
        assert_eq!(
            output["qemu_tcg_conformance"]["coverage"]["aarch64"].as_bool(),
            Some(true)
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["coverage"]["disk_boot"].as_bool(),
            Some(true)
        );
        assert!(output["power_events"].as_array().is_some_and(|values| {
            values.iter().any(|value| value.as_str() == Some("reboot"))
                && values
                    .iter()
                    .any(|value| value.as_str() == Some("poweroff"))
        }));
        assert_eq!(
            output["qemu_tcg_conformance"]["ingestion_path"].as_str(),
            Some("generated_validation_artifacts")
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["generated_validation_projection"]["target"].as_str(),
            Some("apple_mac_studio_m1_pro_sim")
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["generated_validation_projection"]["workload_class"]
                .as_str(),
            Some("generated_validation_apple_mac_studio_m1_pro_sim")
        );
        assert_eq!(
            output["qemu_tcg_conformance"]["generated_validation_projection"]["guest_run_lineage"]
                .as_str(),
            Some("runner_qemu_tcg_conformance_apple_mac_studio_m1_pro_sim")
        );
        assert!(
            output["qemu_tcg_conformance"]["generated_validation_projection"]["scenario_rows"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| {
                    value["scenario"].as_str() == Some("cold_boot")
                        && value["backend"].as_str() == Some("qemu-tcg-aarch64")
                        && value["observe_engine"].as_str() == Some("qemu")
                }))
        );
    }

    #[test]
    fn parser_accepts_supervise_mode_and_heartbeat_controls() {
        let args = vec![
            String::from("--session"),
            String::from("urs_supervise_1"),
            String::from("--instance"),
            String::from("uvi_supervise_1"),
            String::from("--runner-mode"),
            String::from("supervise"),
            String::from("--heartbeat-interval-ms"),
            String::from("250"),
            String::from("--max-heartbeats"),
            String::from("3"),
            String::from("--stop-sentinel"),
            String::from("/tmp/runner.stop"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--disk"),
            String::from("object://images/linux.raw"),
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(config.runner_mode, RunnerMode::Supervise);
        assert_eq!(config.heartbeat_interval_ms, 250);
        assert_eq!(config.max_heartbeats, Some(3));
        assert_eq!(config.stop_sentinel.as_deref(), Some("/tmp/runner.stop"));
    }

    #[test]
    fn supervised_core_worker_channel_owns_instance_lifecycle() {
        let local_disk = write_local_artifact("disk", b"software-dbt-supervise-owned-disk");
        let local_firmware =
            write_local_artifact("firmware", b"software-dbt-supervise-owned-firmware");
        let args = vec![
            String::from("--session"),
            String::from("urs_supervise_owned_1"),
            String::from("--instance"),
            String::from("uvi_supervise_owned_1"),
            String::from("--runner-mode"),
            String::from("supervise"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--firmware-artifact"),
            local_firmware,
            String::from("--disk"),
            local_disk,
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
            String::from("--guest-command"),
            String::from("uname -a"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let runner_contract = RunnerExecutionContract::from_values(None, None)
            .unwrap_or_else(|error| panic!("{error}"));
        let localized_artifacts =
            run_block_worker(&runner_contract, &config).unwrap_or_else(|error| panic!("{error}"));
        let core_worker =
            spawn_supervised_core_worker(&runner_contract, &config, localized_artifacts)
                .unwrap_or_else(|error| panic!("{error}"));

        let started = core_worker
            .receive_started()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(started.phase, super::SoftVmPhase::Running);
        assert_eq!(started.guest_command_results.len(), 1);
        assert!(started.boot_witness.guest_control_ready);
        assert!(started.worker_manifest.guest_control_ready);
        assert_eq!(
            started.worker_manifest.manifest_version,
            RUNNER_WORKER_MANIFEST_VERSION
        );
        assert!(!started.worker_manifest.manifest_fingerprint.is_empty());
        let started_block = worker_manifest_entry(&started.worker_manifest.workers, "block");
        let started_net = worker_manifest_entry(&started.worker_manifest.workers, "net");
        assert_eq!(
            started_block["detail"]["disk_image"].as_str(),
            Some(config.disk_image.as_str())
        );
        assert_eq!(
            started_block["detail"]["cdrom_image"].as_str(),
            config.cdrom_image.as_deref()
        );
        assert!(
            started_block["detail"]["artifact_count"]
                .as_u64()
                .is_some_and(|count| count >= 2)
        );
        assert_eq!(
            started_net["detail"]["virtio_net_mmio_present"].as_bool(),
            Some(true)
        );
        assert_eq!(
            started_net["detail"]["guest_control_ready"].as_bool(),
            Some(true)
        );
        assert_eq!(
            started_net["detail"]["host_relay_egress_ready"].as_bool(),
            Some(true)
        );
        assert_eq!(
            started_net["detail"]["network_mode"].as_str(),
            Some(SOFTWARE_DBT_NETWORK_MODE)
        );
        assert_eq!(started_net["detail"]["internet_nat"].as_bool(), Some(true));
        assert_eq!(
            started_net["detail"]["ingress_transport"].as_str(),
            Some(SOFTWARE_DBT_INGRESS_TRANSPORT)
        );
        assert_eq!(
            started_net["detail"]["ingress_http_ready"].as_bool(),
            Some(false)
        );
        assert_eq!(
            started_net["detail"]["ingress_tcp_ready"].as_bool(),
            Some(false)
        );

        let heartbeat = core_worker
            .heartbeat()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(heartbeat.phase, super::SoftVmPhase::Running);
        assert_eq!(heartbeat.heartbeat.sequence, 1);
        assert!(heartbeat.worker_manifest.guest_control_ready);
        assert_eq!(
            heartbeat.worker_manifest.manifest_version,
            RUNNER_WORKER_MANIFEST_VERSION
        );
        assert_eq!(
            heartbeat.worker_manifest.manifest_fingerprint,
            started.worker_manifest.manifest_fingerprint
        );
        assert_eq!(
            heartbeat.worker_manifest.workers,
            started.worker_manifest.workers
        );

        let stopped = core_worker.stop().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(stopped.phase, super::SoftVmPhase::Stopped);
        assert_eq!(stopped.final_heartbeat_sequence, 1);
        assert!(stopped.worker_manifest.guest_control_ready);
        assert_eq!(
            stopped.worker_manifest.manifest_version,
            RUNNER_WORKER_MANIFEST_VERSION
        );
        assert_ne!(
            stopped.worker_manifest.manifest_fingerprint,
            started.worker_manifest.manifest_fingerprint
        );
        let stopped_block = worker_manifest_entry(&stopped.worker_manifest.workers, "block");
        let stopped_net = worker_manifest_entry(&stopped.worker_manifest.workers, "net");
        assert_eq!(stopped_block["state"].as_str(), Some("stopped"));
        assert_eq!(stopped_net["state"].as_str(), Some("stopped"));
        assert_eq!(
            stopped_block["detail"]["artifact_count"].as_u64(),
            started_block["detail"]["artifact_count"].as_u64()
        );
        assert_eq!(
            stopped_net["detail"]["virtio_net_mmio_present"].as_bool(),
            started_net["detail"]["virtio_net_mmio_present"].as_bool()
        );
    }

    #[test]
    fn supervise_mode_emits_lifecycle_and_periodic_heartbeats() {
        let local_disk = write_local_artifact("disk", b"software-dbt-supervise-disk");
        let local_firmware = write_local_artifact("firmware", b"software-dbt-supervise-firmware");
        let args = vec![
            String::from("--session"),
            String::from("urs_supervise_2"),
            String::from("--instance"),
            String::from("uvi_supervise_2"),
            String::from("--runner-mode"),
            String::from("supervise"),
            String::from("--heartbeat-interval-ms"),
            String::from("0"),
            String::from("--max-heartbeats"),
            String::from("2"),
            String::from("--ingress-http-bind"),
            String::from("127.0.0.1:0"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--firmware-artifact"),
            local_firmware.clone(),
            String::from("--disk"),
            local_disk,
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let mut events = Vec::new();
        execute_supervise_with_emitter(config, Some(String::from("software_dbt")), |event| {
            events.push(event);
            Ok(())
        })
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(events[0]["event"].as_str(), Some("lifecycle"));
        assert_eq!(events[0]["state"].as_str(), Some("started"));
        assert!(events[0]["worker_states"].as_array().is_some_and(|values| {
            values
                .iter()
                .any(|value| value.as_str() == Some("supervisor:running"))
        }));
        assert!(
            events[0]["sandbox_layers"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some("seccomp")))
        );
        assert_eq!(
            events[0]["sandbox_enforcement_mode"].as_str(),
            Some("worker_contract")
        );
        assert_eq!(
            events[0]["sandbox_contract_source"].as_str(),
            Some("launch_contract")
        );
        assert_eq!(
            events[0]["worker_manifest_version"].as_str(),
            Some(RUNNER_WORKER_MANIFEST_VERSION)
        );
        assert_eq!(
            events[0]["network_access"]["network_mode"].as_str(),
            Some(SOFTWARE_DBT_NETWORK_MODE)
        );
        assert_eq!(
            events[0]["network_access"]["internet_nat"].as_bool(),
            Some(true)
        );
        assert_eq!(
            events[0]["network_access"]["ingress_http_ready"].as_bool(),
            Some(true)
        );
        assert_eq!(
            events[0]["network_access"]["ingress_tcp_ready"].as_bool(),
            Some(true)
        );
        assert!(
            events[0]["network_access"]["ingress_http_bind"]
                .as_str()
                .is_some_and(|value| value.starts_with("127.0.0.1:"))
        );
        assert!(
            events[0]["network_access"]["ingress_http_url"]
                .as_str()
                .is_some_and(|value| value.starts_with("http://127.0.0.1:"))
        );
        assert!(
            events[0]["network_access"]["ingress_tcp_bind"]
                .as_str()
                .is_some_and(|value| value.starts_with("127.0.0.1:"))
        );
        let started_manifest_fingerprint = worker_manifest_fingerprint(&events[0]).to_string();
        assert!(
            events[0]["workers"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| {
                    value["name"].as_str() == Some("supervisor")
                        && value["execution_scope"].as_str() == Some("lifecycle_orchestration")
                        && value["detail"]["core_control_path"].as_str() == Some("inproc_mpsc_v1")
                }) && values.iter().any(|value| {
                    value["name"].as_str() == Some("core")
                        && value["detail"]["instance_ownership"].as_str() == Some("thread_owned")
                }) && values.iter().any(|value| {
                    value["name"].as_str() == Some("block")
                        && value["detail"]["artifact_count"]
                            .as_u64()
                            .is_some_and(|count| count >= 2)
                }) && values.iter().any(|value| {
                    value["name"].as_str() == Some("net")
                        && value["detail"]["guest_control_ready"].as_bool() == Some(true)
                        && value["detail"]["ingress_http_ready"].as_bool() == Some(true)
                        && value["detail"]["ingress_tcp_ready"].as_bool() == Some(true)
                        && value["detail"]["ingress_http_url"]
                            .as_str()
                            .is_some_and(|url| url.starts_with("http://127.0.0.1:"))
                }))
        );
        assert!(
            events
                .iter()
                .filter(|event| event["event"].as_str() == Some("heartbeat"))
                .count()
                >= 2
        );
        assert!(events.iter().any(|event| {
            event["event"].as_str() == Some("heartbeat")
                && event["heartbeat_sequence"].as_u64() == Some(1)
                && event["guest_control_ready"].as_bool() == Some(true)
                && event["worker_manifest_version"].as_str() == Some(RUNNER_WORKER_MANIFEST_VERSION)
                && worker_manifest_fingerprint(event) == started_manifest_fingerprint.as_str()
                && event["workers"].as_array().is_some_and(|values| {
                    values.iter().any(|value| {
                        value["name"].as_str() == Some("block")
                            && value["state"].as_str() == Some("running")
                            && value["detail"]["artifact_count"]
                                .as_u64()
                                .is_some_and(|count| count >= 2)
                    }) && values.iter().any(|value| {
                        value["name"].as_str() == Some("net")
                            && value["state"].as_str() == Some("running")
                            && value["detail"]["guest_control_ready"].as_bool() == Some(true)
                            && value["detail"]["ingress_http_ready"].as_bool() == Some(true)
                            && value["detail"]["ingress_tcp_ready"].as_bool() == Some(true)
                    })
                })
        }));
        assert!(events.iter().any(|event| {
            event["event"].as_str() == Some("heartbeat")
                && event["heartbeat_sequence"].as_u64() == Some(2)
                && worker_manifest_fingerprint(event) == started_manifest_fingerprint.as_str()
        }));
        assert!(events.iter().any(|event| {
            event["event"].as_str() == Some("lifecycle")
                && event["state"].as_str() == Some("stopping")
                && event["reason"].as_str() == Some("max_heartbeats_reached")
                && event["worker_manifest_version"].as_str() == Some(RUNNER_WORKER_MANIFEST_VERSION)
                && worker_manifest_fingerprint(event) == started_manifest_fingerprint.as_str()
        }));
        assert!(events.iter().any(|event| {
            event["event"].as_str() == Some("lifecycle")
                && event["state"].as_str() == Some("stopped")
                && event["phase"].as_str() == Some("stopped")
                && event["worker_manifest_version"].as_str() == Some(RUNNER_WORKER_MANIFEST_VERSION)
                && worker_manifest_fingerprint(event) != started_manifest_fingerprint.as_str()
                && event["network_access"]["ingress_http_ready"].as_bool() == Some(false)
                && event["network_access"]["ingress_tcp_ready"].as_bool() == Some(false)
                && event["worker_states"].as_array().is_some_and(|values| {
                    values
                        .iter()
                        .any(|value| value.as_str() == Some("supervisor:stopped"))
                })
                && event["workers"].as_array().is_some_and(|values| {
                    values.iter().any(|value| {
                        value["name"].as_str() == Some("block")
                            && value["state"].as_str() == Some("stopped")
                    }) && values.iter().any(|value| {
                        value["name"].as_str() == Some("net")
                            && value["state"].as_str() == Some("stopped")
                            && value["detail"]["guest_control_ready"].as_bool() == Some(true)
                    })
                })
        }));
    }

    #[test]
    fn supervise_mode_stop_sentinel_stops_before_first_heartbeat() {
        let local_disk = write_local_artifact("disk", b"software-dbt-supervise-stop-sentinel-disk");
        let local_firmware =
            write_local_artifact("firmware", b"software-dbt-supervise-stop-sentinel-firmware");
        let sentinel_path = next_temp_path("supervise_stop_sentinel", "stop");
        let _ = fs::remove_file(&sentinel_path);
        let args = vec![
            String::from("--session"),
            String::from("urs_supervise_stop_sentinel_1"),
            String::from("--instance"),
            String::from("uvi_supervise_stop_sentinel_1"),
            String::from("--runner-mode"),
            String::from("supervise"),
            String::from("--heartbeat-interval-ms"),
            String::from("0"),
            String::from("--stop-sentinel"),
            sentinel_path.to_string_lossy().to_string(),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--firmware-artifact"),
            local_firmware,
            String::from("--disk"),
            local_disk,
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let (_control_tx, control_rx) = mpsc::channel::<String>();
        let mut events = Vec::new();
        execute_supervise_with_emitter_and_control(
            config,
            Some(String::from("software_dbt")),
            Some(control_rx),
            |event| {
                if event["event"].as_str() == Some("lifecycle")
                    && event["state"].as_str() == Some("started")
                {
                    fs::write(&sentinel_path, b"stop").unwrap_or_else(|error| panic!("{error}"));
                }
                events.push(event);
                Ok(())
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let _ = fs::remove_file(&sentinel_path);

        assert_eq!(events[0]["event"].as_str(), Some("lifecycle"));
        assert_eq!(events[0]["state"].as_str(), Some("started"));
        assert_eq!(
            events[0]["worker_manifest_version"].as_str(),
            Some(RUNNER_WORKER_MANIFEST_VERSION)
        );
        let started_manifest_fingerprint = worker_manifest_fingerprint(&events[0]).to_string();
        assert_eq!(
            events
                .iter()
                .filter(|event| event["event"].as_str() == Some("heartbeat"))
                .count(),
            0
        );
        let stopping_event = events
            .iter()
            .find(|event| {
                event["event"].as_str() == Some("lifecycle")
                    && event["state"].as_str() == Some("stopping")
            })
            .unwrap_or_else(|| panic!("missing stopping lifecycle event"));
        assert_eq!(
            stopping_event["reason"].as_str(),
            Some("stop_sentinel_detected")
        );
        assert_eq!(
            stopping_event["worker_manifest_version"].as_str(),
            Some(RUNNER_WORKER_MANIFEST_VERSION)
        );
        assert_eq!(
            worker_manifest_fingerprint(stopping_event),
            started_manifest_fingerprint.as_str()
        );
        assert_eq!(stopping_event["final_heartbeat_sequence"].as_u64(), Some(0));
        let stopped_event = events
            .last()
            .unwrap_or_else(|| panic!("missing stopped lifecycle event"));
        assert_eq!(stopped_event["event"].as_str(), Some("lifecycle"));
        assert_eq!(stopped_event["state"].as_str(), Some("stopped"));
        assert_eq!(
            stopped_event["worker_manifest_version"].as_str(),
            Some(RUNNER_WORKER_MANIFEST_VERSION)
        );
        assert_ne!(
            worker_manifest_fingerprint(stopped_event),
            started_manifest_fingerprint.as_str()
        );
        assert_eq!(stopped_event["final_heartbeat_sequence"].as_u64(), Some(0));
    }

    #[test]
    fn supervise_mode_control_command_stops_before_first_heartbeat() {
        let local_disk = write_local_artifact("disk", b"software-dbt-supervise-control-stop-disk");
        let local_firmware =
            write_local_artifact("firmware", b"software-dbt-supervise-control-stop-firmware");
        let args = vec![
            String::from("--session"),
            String::from("urs_supervise_control_stop_1"),
            String::from("--instance"),
            String::from("uvi_supervise_control_stop_1"),
            String::from("--runner-mode"),
            String::from("supervise"),
            String::from("--heartbeat-interval-ms"),
            String::from("0"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--firmware-artifact"),
            local_firmware,
            String::from("--disk"),
            local_disk,
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let (control_tx, control_rx) = mpsc::channel::<String>();
        let mut events = Vec::new();
        execute_supervise_with_emitter_and_control(
            config,
            Some(String::from("software_dbt")),
            Some(control_rx),
            |event| {
                if event["event"].as_str() == Some("lifecycle")
                    && event["state"].as_str() == Some("started")
                {
                    control_tx
                        .send(String::from("stop"))
                        .unwrap_or_else(|error| panic!("{error}"));
                }
                events.push(event);
                Ok(())
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(events[0]["event"].as_str(), Some("lifecycle"));
        assert_eq!(events[0]["state"].as_str(), Some("started"));
        assert_eq!(
            events[0]["worker_manifest_version"].as_str(),
            Some(RUNNER_WORKER_MANIFEST_VERSION)
        );
        let started_manifest_fingerprint = worker_manifest_fingerprint(&events[0]).to_string();
        assert_eq!(
            events
                .iter()
                .filter(|event| event["event"].as_str() == Some("heartbeat"))
                .count(),
            0
        );
        let stopping_event = events
            .iter()
            .find(|event| {
                event["event"].as_str() == Some("lifecycle")
                    && event["state"].as_str() == Some("stopping")
            })
            .unwrap_or_else(|| panic!("missing stopping lifecycle event"));
        assert_eq!(
            stopping_event["reason"].as_str(),
            Some("control_command:stop")
        );
        assert_eq!(
            stopping_event["worker_manifest_version"].as_str(),
            Some(RUNNER_WORKER_MANIFEST_VERSION)
        );
        assert_eq!(
            worker_manifest_fingerprint(stopping_event),
            started_manifest_fingerprint.as_str()
        );
        assert_eq!(stopping_event["final_heartbeat_sequence"].as_u64(), Some(0));
        let stopped_event = events
            .last()
            .unwrap_or_else(|| panic!("missing stopped lifecycle event"));
        assert_eq!(stopped_event["event"].as_str(), Some("lifecycle"));
        assert_eq!(stopped_event["state"].as_str(), Some("stopped"));
        assert_eq!(
            stopped_event["worker_manifest_version"].as_str(),
            Some(RUNNER_WORKER_MANIFEST_VERSION)
        );
        assert_ne!(
            worker_manifest_fingerprint(stopped_event),
            started_manifest_fingerprint.as_str()
        );
        assert_eq!(stopped_event["final_heartbeat_sequence"].as_u64(), Some(0));
    }

    #[test]
    fn supervise_mode_rejects_probe_mode() {
        let args = vec![
            String::from("--session"),
            String::from("urs_supervise_probe_1"),
            String::from("--instance"),
            String::from("uvi_supervise_probe_1"),
            String::from("--runner-mode"),
            String::from("supervise"),
            String::from("--probe-mode"),
            String::from("qemu_tcg"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("bios"),
            String::from("--disk"),
            String::from("object://images/linux.raw"),
            String::from("--cdrom"),
            String::from("object://images/ubuntu-26.04-installer.iso"),
            String::from("--boot-device"),
            String::from("cdrom"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
            String::from("--max-heartbeats"),
            String::from("1"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let error =
            execute_supervise_with_emitter(config, Some(String::from("software_dbt")), |_| Ok(()))
                .err()
                .unwrap_or_else(|| panic!("expected supervise mode probe conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[test]
    fn runner_rejects_non_software_backend_env() {
        let args = vec![
            String::from("--session"),
            String::from("urs_1"),
            String::from("--instance"),
            String::from("uvi_1"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--disk"),
            String::from("object://images/linux.raw"),
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let error = execute(config, Some(String::from("kvm")))
            .err()
            .unwrap_or_else(|| panic!("expected backend conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[test]
    fn runner_accepts_cdrom_install_media_contract() {
        let local_disk = write_local_artifact("disk", b"software-dbt-installer-disk");
        let local_cdrom = write_local_artifact("installer", b"software-dbt-installer-iso");
        let local_firmware = write_local_artifact("firmware", b"software-dbt-installer-firmware");
        let args = vec![
            String::from("--session"),
            String::from("urs_iso_1"),
            String::from("--instance"),
            String::from("uvi_iso_1"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("bios"),
            String::from("--firmware-artifact"),
            local_firmware.clone(),
            String::from("--disk"),
            local_disk.clone(),
            String::from("--cdrom"),
            local_cdrom.clone(),
            String::from("--boot-device"),
            String::from("cdrom"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
            String::from("--guest-command"),
            String::from("unixbench --summary"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let output = execute(config, Some(String::from("software_dbt")))
            .unwrap_or_else(|error| panic!("{error}"));
        let worker_manifest_fingerprint = assert_output_worker_manifest_parity(&output);
        assert_eq!(output["primary_boot_device"].as_str(), Some("cdrom"));
        assert_eq!(output["cdrom_image"].as_str(), Some(local_cdrom.as_str()));
        assert!(output["console_trace"].as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .any(|line| line.contains("installer media preview"))
        }));
        assert!(output["boot_stages"].as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .any(|stage| stage == "native_control:ready")
        }));
        assert_eq!(
            output["native_execution"]["artifact_count"].as_u64(),
            Some(3)
        );
        assert_eq!(output["guest_control"]["benchmark_runs"].as_u64(), Some(1));
        assert!(
            output["guest_control"]["commands"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(|value| value.get("stdout"))
                    .filter_map(serde_json::Value::as_str)
                    .any(|stdout| stdout.contains("System Benchmarks Index Score")))
        );
        assert!(
            output["native_execution"]["guest_memory_allocations"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .any(|value| value["label"].as_str()
                        == Some("file:/var/log/unixbench/latest.log")))
        );
        assert!(
            output["native_execution"]["instruction_trace"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(|value| value.get("opcode"))
                    .filter_map(serde_json::Value::as_str)
                    .any(|opcode| opcode == "guest_unixbench"))
        );
        assert!(
            output["guest_control"]["virtual_files"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .any(|path| path == "/var/log/unixbench/latest.log"))
        );
        assert!(output["workers"].as_array().is_some_and(|values| {
            values.iter().any(|value| {
                value["name"].as_str() == Some("block")
                    && value["detail"]["artifact_count"].as_u64() == Some(3)
                    && value["detail"]["cdrom_image"].as_str() == Some(local_cdrom.as_str())
            })
        }));
        assert!(!worker_manifest_fingerprint.is_empty());
    }

    #[test]
    fn runner_reports_stateful_guest_control_artifacts() {
        let local_disk = write_local_artifact("disk", b"software-dbt-stateful-disk");
        let local_firmware = write_local_artifact("firmware", b"software-dbt-stateful-firmware");
        let args = vec![
            String::from("--session"),
            String::from("urs_stateful_1"),
            String::from("--instance"),
            String::from("uvi_stateful_1"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--firmware-artifact"),
            local_firmware.clone(),
            String::from("--disk"),
            local_disk,
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
            String::from("--guest-command"),
            String::from("echo benchmark-start > /var/tmp/workload-state"),
            String::from("--guest-command"),
            String::from("cat /var/tmp/workload-state"),
            String::from("--guest-command"),
            String::from("sha256sum /var/tmp/workload-state"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let output = execute(config, Some(String::from("software_dbt")))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(output["guest_control"]["history_len"].as_u64(), Some(3));
        assert!(
            output["guest_control"]["virtual_files"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .any(|path| path == "/var/tmp/workload-state"))
        );
        assert!(
            output["guest_control"]["commands"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(|value| value.get("channel"))
                    .filter_map(serde_json::Value::as_str)
                    .all(|channel| channel == "serial"))
        );
        assert!(
            output["guest_control"]["commands"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(|value| value.get("stdout"))
                    .filter_map(serde_json::Value::as_str)
                    .any(|stdout| stdout.contains("benchmark-start\n")))
        );
        assert!(
            output["guest_control"]["command_channels"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| {
                    value["name"].as_str() == Some("serial")
                        && value["tx_count"].as_u64() == Some(3)
                        && value["rx_count"].as_u64() == Some(3)
                }))
        );
        assert!(
            output["guest_control"]["virtual_file_residency"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value["path"].as_str()
                    == Some("/var/tmp/workload-state")
                    && value["resident_guest_address"].as_u64().is_some()))
        );
        assert!(
            output["native_execution"]["instruction_trace"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(|value| value.get("opcode"))
                    .filter_map(serde_json::Value::as_str)
                    .any(|opcode| opcode == "guest_echo_redirect"))
        );
    }

    #[test]
    fn runner_reports_prefixed_guest_command_channels() {
        let local_disk = write_local_artifact("disk", b"software-dbt-channel-disk");
        let local_firmware = write_local_artifact("firmware", b"software-dbt-channel-firmware");
        let args = vec![
            String::from("--session"),
            String::from("urs_channels_1"),
            String::from("--instance"),
            String::from("uvi_channels_1"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--firmware-artifact"),
            local_firmware,
            String::from("--disk"),
            local_disk,
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
            String::from("--guest-command"),
            String::from("serial::uname -a"),
            String::from("--guest-command"),
            String::from("virtio-console::cat /etc/hostname"),
            String::from("--guest-command"),
            String::from("guest-agent::systemctl is-system-running"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let output = execute(config, Some(String::from("software_dbt")))
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            output["guest_control"]["compatibility_projection"]["mode"].as_str(),
            Some("legacy_file_projection")
        );
        assert_eq!(
            output["guest_control"]["commands"]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.get("channel"))
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>()
                }),
            Some(vec!["serial", "virtio-console", "guest-agent"])
        );
        assert!(
            output["guest_control"]["command_channels"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| {
                    value["name"].as_str() == Some("virtio-console")
                        && value["tx_count"].as_u64() == Some(1)
                        && value["rx_count"].as_u64() == Some(1)
                        && value["last_command"].as_str() == Some("cat /etc/hostname")
                }))
        );
        assert!(
            output["guest_control"]["command_channels"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| {
                    value["name"].as_str() == Some("guest-agent")
                        && value["tx_count"].as_u64() == Some(1)
                        && value["rx_count"].as_u64() == Some(1)
                        && value["last_exit_code"].as_i64() == Some(0)
                }))
        );
        assert!(
            output["native_execution"]["mmio_access_log"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .any(|value| value["region_name"].as_str() == Some("virtio_console")))
        );
    }

    #[test]
    fn runner_accepts_microvm_direct_kernel_contract_for_software_backend() {
        let local_disk = write_local_artifact("disk", b"software-dbt-microvm-disk");
        let local_kernel = write_local_artifact("kernel", b"software-dbt-microvm-kernel");
        let args = vec![
            String::from("--session"),
            String::from("urs_1"),
            String::from("--instance"),
            String::from("uvi_1"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            local_kernel.clone(),
            String::from("--firmware-artifact"),
            local_kernel.clone(),
            String::from("--disk"),
            local_disk.clone(),
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("microvm"),
            String::from("--device-model"),
            String::from("virtio_minimal"),
            String::from("--machine-family"),
            String::from("microvm_linux"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let output = execute(config, Some(String::from("software_dbt")))
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(output["boot_medium"].as_str(), Some("direct_kernel"));
        assert_eq!(output["boot_path"].as_str(), Some("microvm"));
        assert_eq!(output["machine_family"].as_str(), Some("microvm_linux"));
        assert_eq!(
            output["firmware_profile"].as_str(),
            Some(local_kernel.as_str())
        );
        assert_eq!(output["primary_boot_device"].as_str(), Some("disk"));
        assert_eq!(output["guest_control_ready"].as_bool(), Some(true));
        assert!(output["boot_stages"].as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .any(|stage| stage == "direct_kernel:entry_complete")
        }));
        assert!(output["console_trace"].as_array().is_some_and(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .any(|line| line.contains("Direct kernel"))
        }));
        assert_eq!(
            output["native_execution"]["artifact_count"].as_u64(),
            Some(2)
        );
        assert!(
            output["native_execution"]["instruction_trace"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(|value| value.get("opcode"))
                    .filter_map(serde_json::Value::as_str)
                    .any(|opcode| opcode == "direct_kernel_entry"))
        );
    }

    #[test]
    fn runner_rejects_microvm_contract_with_cdrom_install_media() {
        let local_disk = write_local_artifact("disk", b"software-dbt-microvm-disk");
        let local_kernel = write_local_artifact("kernel", b"software-dbt-microvm-kernel");
        let local_cdrom = write_local_artifact("iso", b"software-dbt-microvm-installer");
        let args = vec![
            String::from("--session"),
            String::from("urs_1"),
            String::from("--instance"),
            String::from("uvi_1"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            local_kernel.clone(),
            String::from("--firmware-artifact"),
            local_kernel,
            String::from("--disk"),
            local_disk,
            String::from("--cdrom"),
            local_cdrom,
            String::from("--boot-device"),
            String::from("cdrom"),
            String::from("--boot-path"),
            String::from("microvm"),
            String::from("--device-model"),
            String::from("virtio_minimal"),
            String::from("--machine-family"),
            String::from("microvm_linux"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let error = execute(config, Some(String::from("software_dbt")))
            .err()
            .unwrap_or_else(|| panic!("expected direct-kernel contract conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[test]
    fn parser_accepts_supervise_flags() {
        let args = vec![
            String::from("--session"),
            String::from("urs_supervise_1"),
            String::from("--instance"),
            String::from("uvi_supervise_1"),
            String::from("--runner-mode"),
            String::from("supervise"),
            String::from("--heartbeat-interval-ms"),
            String::from("0"),
            String::from("--max-heartbeats"),
            String::from("2"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--disk"),
            String::from("object://images/linux.raw"),
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(config.runner_mode, RunnerMode::Supervise);
        assert_eq!(config.heartbeat_interval_ms, 0);
        assert_eq!(config.max_heartbeats, Some(2));
    }

    #[test]
    fn supervise_mode_emits_lifecycle_and_heartbeat_stream() {
        let local_disk = write_local_artifact("disk", b"software-dbt-stream-disk");
        let local_firmware = write_local_artifact("firmware", b"software-dbt-stream-firmware");
        let args = vec![
            String::from("--session"),
            String::from("urs_supervise_2"),
            String::from("--instance"),
            String::from("uvi_supervise_2"),
            String::from("--runner-mode"),
            String::from("supervise"),
            String::from("--heartbeat-interval-ms"),
            String::from("0"),
            String::from("--max-heartbeats"),
            String::from("3"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--firmware-artifact"),
            local_firmware.clone(),
            String::from("--disk"),
            local_disk,
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
            String::from("--guest-command"),
            String::from("uname -a"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let mut events = Vec::new();
        execute_supervise_with_emitter(config, Some(String::from("software_dbt")), |event| {
            events.push(event);
            Ok(())
        })
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            events.first().and_then(|value| value["event"].as_str()),
            Some("lifecycle")
        );
        assert_eq!(
            events.first().and_then(|value| value["state"].as_str()),
            Some("started")
        );
        let started_event = events
            .first()
            .unwrap_or_else(|| panic!("missing lifecycle start event"));
        assert_eq!(started_event["guest_control_ready"].as_bool(), Some(true));
        assert_eq!(
            started_event["worker_manifest_version"].as_str(),
            Some(RUNNER_WORKER_MANIFEST_VERSION)
        );
        let started_manifest_fingerprint = worker_manifest_fingerprint(started_event).to_string();
        assert_eq!(
            started_event["sandbox_enforcement_mode"].as_str(),
            Some("worker_contract")
        );
        assert_eq!(
            started_event["sandbox_contract_source"].as_str(),
            Some("launch_contract")
        );
        assert!(
            started_event["boot_stages"]
                .as_array()
                .is_some_and(|values| {
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .any(|stage| stage == "native_control:ready")
                })
        );
        assert!(
            started_event["console_trace"]
                .as_array()
                .is_some_and(|values| {
                    values
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .any(|line| line.contains("guest control handoff"))
                })
        );
        assert!(
            started_event["workers"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| {
                    value["name"].as_str() == Some("block")
                        && value["execution_scope"].as_str() == Some("artifact_staging")
                        && value["detail"]["artifact_count"]
                            .as_u64()
                            .is_some_and(|count| count >= 2)
                }) && values.iter().any(|value| {
                    value["name"].as_str() == Some("core")
                        && value["detail"]["instance_ownership"].as_str() == Some("thread_owned")
                }) && values.iter().any(|value| {
                    value["name"].as_str() == Some("net")
                        && value["detail"]["guest_control_ready"].as_bool() == Some(true)
                }))
        );
        assert_eq!(
            events.last().and_then(|value| value["event"].as_str()),
            Some("lifecycle")
        );
        assert_eq!(
            events.last().and_then(|value| value["state"].as_str()),
            Some("stopped")
        );

        let heartbeat_events = events
            .iter()
            .filter(|event| event["event"].as_str() == Some("heartbeat"))
            .collect::<Vec<_>>();
        assert_eq!(heartbeat_events.len(), 3);
        assert_eq!(heartbeat_events[0]["heartbeat_sequence"].as_u64(), Some(1));
        assert_eq!(heartbeat_events[2]["heartbeat_sequence"].as_u64(), Some(3));
        assert!(heartbeat_events.iter().all(|event| {
            event["guest_control_ready"].as_bool() == Some(true)
                && event["worker_manifest_version"].as_str() == Some(RUNNER_WORKER_MANIFEST_VERSION)
                && worker_manifest_fingerprint(event) == started_manifest_fingerprint.as_str()
                && event["workers"].as_array().is_some_and(|values| {
                    values.iter().any(|value| {
                        value["name"].as_str() == Some("block")
                            && value["state"].as_str() == Some("running")
                            && value["detail"]["artifact_count"]
                                .as_u64()
                                .is_some_and(|count| count >= 2)
                    }) && values.iter().any(|value| {
                        value["name"].as_str() == Some("net")
                            && value["state"].as_str() == Some("running")
                            && value["detail"]["guest_control_ready"].as_bool() == Some(true)
                    })
                })
        }));
        assert!(events.iter().any(|event| {
            event["event"].as_str() == Some("guest_commands")
                && event["results"]
                    .as_array()
                    .is_some_and(|results| !results.is_empty())
        }));
        let stopping_event = events
            .iter()
            .find(|event| {
                event["event"].as_str() == Some("lifecycle")
                    && event["state"].as_str() == Some("stopping")
            })
            .unwrap_or_else(|| panic!("missing stopping lifecycle event"));
        assert_eq!(
            stopping_event["reason"].as_str(),
            Some("max_heartbeats_reached")
        );
        assert_eq!(
            stopping_event["worker_manifest_version"].as_str(),
            Some(RUNNER_WORKER_MANIFEST_VERSION)
        );
        assert_eq!(
            worker_manifest_fingerprint(stopping_event),
            started_manifest_fingerprint.as_str()
        );
        assert_eq!(stopping_event["final_heartbeat_sequence"].as_u64(), Some(3));
        let stopped_event = events
            .last()
            .unwrap_or_else(|| panic!("missing stopped lifecycle event"));
        assert_eq!(
            stopped_event["worker_manifest_version"].as_str(),
            Some(RUNNER_WORKER_MANIFEST_VERSION)
        );
        assert_ne!(
            worker_manifest_fingerprint(stopped_event),
            started_manifest_fingerprint.as_str()
        );
        assert_eq!(stopped_event["final_heartbeat_sequence"].as_u64(), Some(3));
    }

    #[test]
    fn supervise_mode_serves_guest_webroot_over_managed_ingress() {
        let local_disk = write_local_artifact("disk", b"software-dbt-managed-ingress-disk");
        let local_firmware =
            write_local_artifact("firmware", b"software-dbt-managed-ingress-firmware");
        let args = vec![
            String::from("--session"),
            String::from("urs_supervise_ingress_1"),
            String::from("--instance"),
            String::from("uvi_supervise_ingress_1"),
            String::from("--runner-mode"),
            String::from("supervise"),
            String::from("--heartbeat-interval-ms"),
            String::from("0"),
            String::from("--ingress-http-bind"),
            String::from("127.0.0.1:0"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--firmware-artifact"),
            local_firmware,
            String::from("--disk"),
            local_disk,
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
            String::from("--guest-command"),
            String::from("echo managed ingress works > /var/www/index.html"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let (event_tx, event_rx) = mpsc::channel();
        let (control_tx, control_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            execute_supervise_with_emitter_and_control(
                config,
                Some(String::from("software_dbt")),
                Some(control_rx),
                move |event| {
                    event_tx.send(event).map_err(|_| {
                        uhost_core::PlatformError::unavailable("test event channel disconnected")
                    })?;
                    Ok(())
                },
            )
        });

        let started = loop {
            let event = event_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_else(|error| panic!("{error}"));
            if event["event"].as_str() == Some("lifecycle")
                && event["state"].as_str() == Some("started")
            {
                break event;
            }
        };
        let ingress_url = started["network_access"]["ingress_http_url"]
            .as_str()
            .unwrap_or_else(|| panic!("missing managed ingress url"))
            .to_owned();
        let body = http_get_text(&ingress_url);
        assert_eq!(body, "managed ingress works\n");

        control_tx
            .send(String::from("stop"))
            .unwrap_or_else(|error| panic!("{error}"));
        handle
            .join()
            .unwrap_or_else(|_| panic!("runner supervise thread panicked"))
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn supervise_mode_serves_managed_tcp_ingress() {
        let local_disk = write_local_artifact("disk", b"software-dbt-managed-tcp-disk");
        let local_firmware = write_local_artifact("firmware", b"software-dbt-managed-tcp-fw");
        let args = vec![
            String::from("--session"),
            String::from("urs_supervise_ingress_tcp_1"),
            String::from("--instance"),
            String::from("uvi_supervise_ingress_tcp_1"),
            String::from("--runner-mode"),
            String::from("supervise"),
            String::from("--heartbeat-interval-ms"),
            String::from("0"),
            String::from("--ingress-http-bind"),
            String::from("127.0.0.1:0"),
            String::from("--ingress-tcp-bind"),
            String::from("127.0.0.1:0"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--firmware-artifact"),
            local_firmware,
            String::from("--disk"),
            local_disk,
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let (event_tx, event_rx) = mpsc::channel();
        let (control_tx, control_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            execute_supervise_with_emitter_and_control(
                config,
                Some(String::from("software_dbt")),
                Some(control_rx),
                move |event| {
                    event_tx.send(event).map_err(|_| {
                        uhost_core::PlatformError::unavailable("test event channel disconnected")
                    })?;
                    Ok(())
                },
            )
        });

        let started = loop {
            let event = event_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_else(|error| panic!("{error}"));
            if event["event"].as_str() == Some("lifecycle")
                && event["state"].as_str() == Some("started")
            {
                break event;
            }
        };
        let tcp_bind = started["network_access"]["ingress_tcp_bind"]
            .as_str()
            .unwrap_or_else(|| panic!("missing managed tcp ingress bind"))
            .to_owned();
        let response = tcp_exchange_text(&tcp_bind, "hello over tcp\n");
        assert!(response.contains("UHost managed TCP ingress ready"));
        assert!(response.contains("hello over tcp\n"));

        control_tx
            .send(String::from("stop"))
            .unwrap_or_else(|error| panic!("{error}"));
        handle
            .join()
            .unwrap_or_else(|_| panic!("runner supervise thread panicked"))
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn supervise_mode_serves_guest_owned_udp_ingress() {
        let local_disk = write_local_artifact("disk", b"software-dbt-managed-udp-disk");
        let local_firmware = write_local_artifact("firmware", b"software-dbt-managed-udp-fw");
        let args = vec![
            String::from("--session"),
            String::from("urs_supervise_ingress_udp_1"),
            String::from("--instance"),
            String::from("uvi_supervise_ingress_udp_1"),
            String::from("--runner-mode"),
            String::from("supervise"),
            String::from("--heartbeat-interval-ms"),
            String::from("0"),
            String::from("--ingress-http-bind"),
            String::from("127.0.0.1:0"),
            String::from("--ingress-tcp-bind"),
            String::from("127.0.0.1:0"),
            String::from("--ingress-udp-bind"),
            String::from("127.0.0.1:0"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("uefi_standard"),
            String::from("--firmware-artifact"),
            local_firmware,
            String::from("--disk"),
            local_disk,
            String::from("--boot-device"),
            String::from("disk"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
            String::from("--guest-command"),
            String::from("echo static_response > /run/guest-ingress/udp/services/default/mode"),
            String::from("--guest-command"),
            String::from("echo guest-owned-udp > /run/guest-ingress/udp/services/default/response"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let (event_tx, event_rx) = mpsc::channel();
        let (control_tx, control_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            execute_supervise_with_emitter_and_control(
                config,
                Some(String::from("software_dbt")),
                Some(control_rx),
                move |event| {
                    event_tx.send(event).map_err(|_| {
                        uhost_core::PlatformError::unavailable("test event channel disconnected")
                    })?;
                    Ok(())
                },
            )
        });

        let started = loop {
            let event = event_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_else(|error| panic!("{error}"));
            if event["event"].as_str() == Some("lifecycle")
                && event["state"].as_str() == Some("started")
            {
                break event;
            }
        };
        let udp_bind = started["network_access"]["ingress_udp_bind"]
            .as_str()
            .unwrap_or_else(|| panic!("missing managed udp ingress bind"))
            .to_owned();
        assert_eq!(
            started["network_access"]["network_mode"].as_str(),
            Some(SOFTWARE_DBT_NETWORK_MODE)
        );
        assert_eq!(
            started["network_access"]["ingress_udp_ready"].as_bool(),
            Some(true)
        );
        let response = udp_exchange_text(&udp_bind, "hello over udp\n");
        assert_eq!(response, "guest-owned-udp\n");

        control_tx
            .send(String::from("stop"))
            .unwrap_or_else(|error| panic!("{error}"));
        handle
            .join()
            .unwrap_or_else(|_| panic!("runner supervise thread panicked"))
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn supervise_mode_rejects_probe_harness_contract() {
        let args = vec![
            String::from("--session"),
            String::from("urs_supervise_3"),
            String::from("--instance"),
            String::from("uvi_supervise_3"),
            String::from("--runner-mode"),
            String::from("supervise"),
            String::from("--probe-mode"),
            String::from("qemu_tcg"),
            String::from("--arch"),
            String::from("x86_64"),
            String::from("--vcpu"),
            String::from("2"),
            String::from("--memory-mb"),
            String::from("2048"),
            String::from("--firmware"),
            String::from("bios"),
            String::from("--disk"),
            String::from("object://images/linux.raw"),
            String::from("--cdrom"),
            String::from("object://images/ubuntu-26.04-installer.iso"),
            String::from("--boot-device"),
            String::from("cdrom"),
            String::from("--boot-path"),
            String::from("general_purpose"),
            String::from("--device-model"),
            String::from("virtio_balanced"),
            String::from("--machine-family"),
            String::from("general_purpose_pci"),
            String::from("--execution-class"),
            String::from("balanced"),
            String::from("--restart-policy"),
            String::from("on-failure"),
            String::from("--migration-kind"),
            String::from("crash_consistent"),
        ];
        let config = RunnerConfig::parse(&args).unwrap_or_else(|error| panic!("{error}"));
        let error =
            execute_supervise_with_emitter(config, Some(String::from("software_dbt")), |_| Ok(()))
                .err()
                .unwrap_or_else(|| panic!("expected supervise/probe_mode conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }
}
