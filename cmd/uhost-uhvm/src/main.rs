//! Command-line interface for the uHVM virtual machine.

use std::{env, ffi::OsString, path::PathBuf, process::ExitCode, time::Instant};

use serde_json::json;
use uhost_uhvm::{DriveConfig, SeccompLevel, SerialSink, UhvmConfig, Vmm, VmmExit};

const DEFAULT_CMDLINE: &str = "console=ttyS0 reboot=k panic=1 pci=off nomodule 8250.nr_uarts=1 i8042.noaux i8042.nomux i8042.dumbkbd root=/dev/vda rw";

struct Arguments {
    kernel: Option<PathBuf>,
    rootfs: Option<PathBuf>,
    rootfs_read_only: bool,
    mem_mib: u64,
    vcpus: u8,
    cmdline: Option<String>,
    seccomp: SeccompLevel,
    serial: SerialSink,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{}", json!({"event": "error", "message": error}));
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let Some(args) = parse_arguments(env::args_os().skip(1))? else {
        return Ok(ExitCode::SUCCESS);
    };
    let kernel = args
        .kernel
        .ok_or_else(|| String::from("required argument --kernel is missing"))?;
    let rootfs = args
        .rootfs
        .ok_or_else(|| String::from("required argument --rootfs is missing"))?;
    let root_mode = if args.rootfs_read_only { "ro" } else { "rw" };
    let base_cmdline = DEFAULT_CMDLINE.strip_suffix("rw").map_or_else(
        || String::from(DEFAULT_CMDLINE),
        |cmdline| format!("{cmdline}{root_mode}"),
    );
    let cmdline = match args.cmdline {
        Some(extra) if !extra.trim().is_empty() => format!("{base_cmdline} {extra}"),
        _ => base_cmdline,
    };
    eprintln!(
        "{}",
        json!({
            "event": "vmm_started",
            "kernel": kernel,
            "rootfs": rootfs,
            "mem_mib": args.mem_mib,
            "vcpus": args.vcpus,
            "seccomp": seccomp_name(args.seccomp),
        })
    );
    let started = Instant::now();
    let result = Vmm::boot(UhvmConfig {
        kernel,
        cmdline,
        mem_mib: args.mem_mib,
        vcpus: args.vcpus,
        drives: vec![DriveConfig {
            path: rootfs,
            read_only: args.rootfs_read_only,
            is_root: true,
        }],
        serial: args.serial,
        seccomp: args.seccomp,
    });
    let elapsed = started.elapsed().as_millis();
    match result {
        Ok(VmmExit::GuestReset) => {
            eprintln!(
                "{}",
                json!({"event": "guest_exit", "reason": "reset", "boot_to_exit_ms": elapsed})
            );
            Ok(ExitCode::SUCCESS)
        }
        Ok(VmmExit::GuestShutdown) => {
            eprintln!(
                "{}",
                json!({"event": "guest_exit", "reason": "shutdown", "boot_to_exit_ms": elapsed})
            );
            Ok(ExitCode::SUCCESS)
        }
        Ok(VmmExit::Error(message)) => {
            eprintln!(
                "{}",
                json!({"event": "guest_exit", "reason": "error", "message": message, "boot_to_exit_ms": elapsed})
            );
            Ok(ExitCode::FAILURE)
        }
        Err(error) => {
            eprintln!(
                "{}",
                json!({"event": "guest_exit", "reason": "error", "message": error.to_string(), "boot_to_exit_ms": elapsed})
            );
            Err(error.to_string())
        }
    }
}

fn parse_arguments(arguments: impl Iterator<Item = OsString>) -> Result<Option<Arguments>, String> {
    let mut parsed = Arguments {
        kernel: None,
        rootfs: None,
        rootfs_read_only: false,
        mem_mib: 256,
        vcpus: 1,
        cmdline: None,
        seccomp: SeccompLevel::Kill,
        serial: SerialSink::Stdout,
    };
    let mut arguments = arguments;
    while let Some(argument) = arguments.next() {
        let flag = argument
            .into_string()
            .map_err(|_| String::from("command-line flags must be UTF-8"))?;
        match flag.as_str() {
            "--kernel" => parsed.kernel = Some(PathBuf::from(next_value(&mut arguments, &flag)?)),
            "--rootfs" => parsed.rootfs = Some(PathBuf::from(next_value(&mut arguments, &flag)?)),
            "--rootfs-ro" => parsed.rootfs_read_only = true,
            "--mem-mib" => {
                parsed.mem_mib = parse_number(&next_value(&mut arguments, &flag)?, &flag)?
            }
            "--vcpus" => parsed.vcpus = parse_number(&next_value(&mut arguments, &flag)?, &flag)?,
            "--cmdline" => parsed.cmdline = Some(next_value(&mut arguments, &flag)?),
            "--seccomp" => {
                parsed.seccomp = match next_value(&mut arguments, &flag)?.as_str() {
                    "kill" => SeccompLevel::Kill,
                    "log" => SeccompLevel::Log,
                    "off" => SeccompLevel::Off,
                    value => return Err(format!("invalid seccomp level: {value}")),
                }
            }
            "--serial" => {
                let value = next_value(&mut arguments, &flag)?;
                parsed.serial = if value == "stdio" {
                    SerialSink::Stdout
                } else if let Some(path) = value.strip_prefix("file:") {
                    if path.is_empty() {
                        return Err("--serial file: requires a path".to_owned());
                    }
                    SerialSink::File(PathBuf::from(path))
                } else {
                    return Err(format!("invalid serial sink: {value}"));
                };
            }
            "--help" | "-h" => {
                print_help();
                return Ok(None);
            }
            _ => return Err(format!("unknown argument: {flag}")),
        }
    }
    Ok(Some(parsed))
}

fn next_value(
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))?
        .into_string()
        .map_err(|_| format!("{flag} value must be UTF-8"))
}

fn parse_number<T: std::str::FromStr>(value: &str, flag: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("invalid numeric value for {flag}: {value}"))
}

fn seccomp_name(level: SeccompLevel) -> &'static str {
    match level {
        SeccompLevel::Off => "off",
        SeccompLevel::Log => "log",
        SeccompLevel::Kill => "kill",
    }
}

fn print_help() {
    println!(
        "Usage: uhost-uhvm --kernel PATH --rootfs PATH [--rootfs-ro] [--mem-mib 256] [--vcpus 1] [--cmdline STR] [--seccomp kill|log|off] [--serial stdio|file:PATH]"
    );
}

#[cfg(test)]
mod tests {
    use super::parse_arguments;
    use std::ffi::OsString;

    #[test]
    fn parser_rejects_unknown_flags() {
        let arguments = [OsString::from("--unknown")];
        assert!(parse_arguments(arguments.into_iter()).is_err());
    }
}
