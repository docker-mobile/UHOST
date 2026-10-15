//! KVM-backed guest boot integration test.

use std::{
    env,
    error::Error,
    fs,
    io::Write,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[test]
#[ignore = "requires KVM and UHVM_TEST_KERNEL/UHVM_TEST_ROOTFS"]
fn boots_guest_and_round_trips_serial_input() -> Result<(), Box<dyn Error>> {
    let kernel = env::var("UHVM_TEST_KERNEL")?;
    let rootfs = env::var("UHVM_TEST_ROOTFS")?;
    let serial_path = env::temp_dir().join(format!("uhvm-test-serial-{}.log", std::process::id()));
    let serial_sink = format!("file:{}", serial_path.display());
    let output = Command::new(env!("CARGO_BIN_EXE_uhost-uhvm"))
        .args([
            "--kernel",
            &kernel,
            "--rootfs",
            &rootfs,
            "--vcpus",
            "2",
            "--mem-mib",
            "512",
            "--seccomp",
            "kill",
            "--serial",
            &serial_sink,
            "--cmdline",
            "init=/bin/sh -- -c \"mount -t proc proc /proc; echo UHVM_BOOT_OK; echo nproc=$(nproc); read -r memline </proc/meminfo; echo $memline; dd if=/dev/vda of=/dev/null bs=1M count=64 status=none && echo UHVM_DISK_READ_OK; sync; reboot -f\"",
        ])
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "VMM exited with {}: {stderr}",
        output.status
    );
    let serial = fs::read_to_string(&serial_path)?;
    let _ = fs::remove_file(&serial_path);
    assert!(
        serial.contains("PnP ACPI: found"),
        "guest did not discover ACPI PnP devices"
    );
    assert!(
        serial.contains("ttyS0 at I/O 0x3f8 (irq =") && serial.contains("is a 16550A"),
        "guest did not identify COM1 as a 16550A"
    );
    assert!(
        serial
            .lines()
            .any(|line| line.trim_end_matches('\r').trim() == "UHVM_BOOT_OK"),
        "serial output missing boot marker"
    );
    assert!(
        serial
            .lines()
            .any(|line| line.trim_end_matches('\r').trim() == "nproc=2"),
        "guest did not report two vCPUs"
    );
    assert!(serial.contains("MemTotal:"), "guest did not report memory");
    assert!(
        serial
            .lines()
            .any(|line| line.trim_end_matches('\r').trim() == "UHVM_DISK_READ_OK"),
        "guest did not finish disk read"
    );
    assert!(
        stderr.contains("\"reason\":\"reset\""),
        "VMM did not report guest reset: {stderr}"
    );

    let input_serial_path =
        env::temp_dir().join(format!("uhvm-test-input-serial-{}.log", std::process::id()));
    let input_serial_sink = format!("file:{}", input_serial_path.display());
    let mut child = Command::new(env!("CARGO_BIN_EXE_uhost-uhvm"))
        .args([
            "--kernel",
            &kernel,
            "--rootfs",
            &rootfs,
            "--vcpus",
            "2",
            "--mem-mib",
            "512",
            "--seccomp",
            "kill",
            "--serial",
            &input_serial_sink,
            "--cmdline",
            "init=/bin/sh",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("VMM stdin was not piped"))?;
    thread::sleep(Duration::from_secs(3));
    stdin.write_all(b"echo UHVM_TTY_$((6*7))\nreboot -f\n")?;
    drop(stdin);

    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            child.kill()?;
            let output = child.wait_with_output()?;
            return Err(format!(
                "interactive VMM did not exit: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        thread::sleep(Duration::from_millis(100));
    }
    let output = child.wait_with_output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "interactive VMM exited with {}: {stderr}",
        output.status
    );
    let input_serial = fs::read_to_string(&input_serial_path)?;
    let _ = fs::remove_file(&input_serial_path);
    assert!(
        input_serial
            .lines()
            .any(|line| line.trim_end_matches('\r').trim() == "UHVM_TTY_42"),
        "guest did not execute host-provided serial input"
    );
    assert!(
        stderr.contains("\"reason\":\"reset\""),
        "interactive guest did not report reset: {stderr}"
    );
    Ok(())
}
