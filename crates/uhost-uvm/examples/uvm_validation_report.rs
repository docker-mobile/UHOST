use std::env;

use uhost_uvm::{
    BenchmarkWorkload, ValidationTarget, generate_validation_report, infer_host_capacity_profile,
};

fn parse_target(value: &str) -> ValidationTarget {
    match value.trim().to_ascii_lowercase().as_str() {
        "host" => ValidationTarget::Host,
        "ubuntu" | "ubuntu2204" | "ubuntu_22_04_vm" => ValidationTarget::Ubuntu2204Vm,
        "apple" | "apple_m1" | "apple_mac_studio_m1_pro_sim" => {
            ValidationTarget::AppleMacStudioM1ProSim
        }
        _ => ValidationTarget::Ubuntu2204Vm,
    }
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let target = args
        .get(1)
        .map(|value| parse_target(value))
        .unwrap_or(ValidationTarget::Ubuntu2204Vm);
    let report = generate_validation_report(
        infer_host_capacity_profile(),
        BenchmarkWorkload {
            name: String::from("default-validation"),
            vcpu: if matches!(target, ValidationTarget::AppleMacStudioM1ProSim) {
                8
            } else {
                4
            },
            memory_mb: if matches!(target, ValidationTarget::AppleMacStudioM1ProSim) {
                8 * 1024
            } else {
                4 * 1024
            },
            dirty_page_rate_mbps: 256,
            io_intensity: 48,
            stress_iterations: 4_000,
        },
        target,
    )
    .unwrap_or_else(|error| panic!("{error}"));

    println!("{}", report.render_markdown());
}
