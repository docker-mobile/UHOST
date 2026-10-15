use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::{Result, SeccompLevel, UhvmError};

const KVM_RUN_IOCTL: u64 = 0xae80;

const VCPU_SYSCALLS: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_writev,
    libc::SYS_ioctl,
    libc::SYS_futex,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_clock_gettime,
    libc::SYS_sched_yield,
    libc::SYS_restart_syscall,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_close,
    libc::SYS_fcntl,
    libc::SYS_gettid,
    libc::SYS_getpid,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_madvise,
    libc::SYS_brk,
    libc::SYS_fstat,
    libc::SYS_lseek,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_arch_prctl,
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
];

const VMM_SYSCALLS: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_writev,
    libc::SYS_futex,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_clock_gettime,
    libc::SYS_sched_yield,
    libc::SYS_restart_syscall,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_close,
    libc::SYS_fcntl,
    libc::SYS_gettid,
    libc::SYS_getpid,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_madvise,
    libc::SYS_brk,
    libc::SYS_fstat,
    libc::SYS_lseek,
    libc::SYS_nanosleep,
    libc::SYS_arch_prctl,
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
];

/// Installs the vCPU syscall filter on the current thread.
pub fn apply_vcpu_filter(level: SeccompLevel) -> Result<()> {
    apply_filter(level, VCPU_SYSCALLS, true)
}

/// Installs the VMM/device syscall filter on the current thread.
pub fn apply_vmm_filter(level: SeccompLevel) -> Result<()> {
    apply_filter(level, VMM_SYSCALLS, false)
}

fn apply_filter(level: SeccompLevel, syscalls: &[i64], vcpu: bool) -> Result<()> {
    if level == SeccompLevel::Off {
        return Ok(());
    }
    let mut rules = syscalls
        .iter()
        .copied()
        .map(|syscall| (syscall, Vec::new()))
        .collect::<BTreeMap<_, _>>();
    if vcpu {
        let condition =
            SeccompCondition::new(1, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, KVM_RUN_IOCTL)
                .map_err(|error| UhvmError::new(format!("build KVM ioctl filter: {error}")))?;
        let rule = SeccompRule::new(vec![condition])
            .map_err(|error| UhvmError::new(format!("build KVM ioctl rule: {error}")))?;
        rules.insert(libc::SYS_ioctl, vec![rule]);
    }
    let condition = SeccompCondition::new(
        1,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        libc::F_GETFD as u64,
    )
    .map_err(|error| UhvmError::new(format!("build fcntl filter: {error}")))?;
    let rule = SeccompRule::new(vec![condition])
        .map_err(|error| UhvmError::new(format!("build fcntl rule: {error}")))?;
    rules.insert(libc::SYS_fcntl, vec![rule]);
    for syscall in [libc::SYS_mmap, libc::SYS_mprotect] {
        let condition = SeccompCondition::new(
            2,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
            0,
        )
        .map_err(|error| UhvmError::new(format!("build executable mapping filter: {error}")))?;
        let rule = SeccompRule::new(vec![condition])
            .map_err(|error| UhvmError::new(format!("build executable mapping rule: {error}")))?;
        rules.insert(syscall, vec![rule]);
    }
    let default_action = match level {
        SeccompLevel::Off => SeccompAction::Allow,
        SeccompLevel::Log => SeccompAction::Log,
        SeccompLevel::Kill => SeccompAction::KillProcess,
    };
    let filter = SeccompFilter::new(
        rules,
        default_action,
        SeccompAction::Allow,
        TargetArch::x86_64,
    )
    .map_err(|error| UhvmError::new(format!("build seccomp filter: {error}")))?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|error| UhvmError::new(format!("compile seccomp filter: {error}")))?;
    seccompiler::apply_filter(&program)
        .map_err(|error| UhvmError::new(format!("install seccomp filter: {error}")))
}
