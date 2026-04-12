#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  exec bash "$REPO_ROOT/scripts/with-disposable-target-dir.sh" uvm-stack-validation bash "$0" "$@"
fi
cd "$REPO_ROOT"

TARGETS=(host ubuntu apple)
OUT_DIR="docs/benchmarks/generated"
MANIFEST_PATH="$OUT_DIR/uvm-stack-validation-manifest.json"
RUN_CLOUDIMG_GUEST_CONTROL="${UHOST_RUN_CLOUDIMG_GUEST_CONTROL:-0}"
MANIFEST_ONLY="${UHOST_UVM_STACK_VALIDATION_MANIFEST_ONLY:-0}"
CLOUDIMG_SUMMARY_PATH="$OUT_DIR/qemu-tcg-cloudimg-guest-control.json"
CLOUDIMG_CONSOLE_LOG_PATH="$OUT_DIR/qemu-tcg-cloudimg-console.log"
CLOUDIMG_UNIXBENCH_LOG_PATH="$OUT_DIR/qemu-tcg-cloudimg-unixbench.log"
LEGACY_BOOT_PROBE_LOG_PATH="$OUT_DIR/qemu-tcg-ubuntu-26.04-boot-probe.log"
mkdir -p "$OUT_DIR"

sha256_artifact() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
    return
  fi

  echo 'missing sha256 checksum utility (expected sha256sum or shasum)' >&2
  exit 1
}

extract_report_generated_at() {
  local path="$1"
  local generated_at
  generated_at="$(sed -n 's/^- Generated at: //p' "$path" | head -n 1)"
  if [ -z "$generated_at" ]; then
    echo "failed to extract generated timestamp from $path" >&2
    exit 1
  fi

  printf '%s' "$generated_at"
}

json_array_of_strings() {
  local first=1
  local value

  printf '['
  for value in "$@"; do
    if [ "$first" -eq 0 ]; then
      printf ', '
    fi
    printf '"%s"' "$value"
    first=0
  done
  printf ']'
}

cleanup_manifest_excluded_artifacts() {
  rm -f "$LEGACY_BOOT_PROBE_LOG_PATH"
  if [ "$RUN_CLOUDIMG_GUEST_CONTROL" != "1" ]; then
    rm -f "$CLOUDIMG_SUMMARY_PATH" "$CLOUDIMG_CONSOLE_LOG_PATH" "$CLOUDIMG_UNIXBENCH_LOG_PATH"
  fi
}

emit_validation_manifest() {
  local manifest_generated_at
  local script_sha
  local focused_gate_sha
  local wave3_evidence_test_sha
  local host_generated_at
  local ubuntu_generated_at
  local apple_generated_at
  local host_sha
  local ubuntu_sha
  local apple_sha
  local installer_sha
  local disk_sha
  local native_sha
  local qemu_summary_sha
  local qemu_raw_sha
  local qemu_text_sha
  local qemu_kernel_sha
  local qemu_probe_evidence_references_json
  local host_report_references_json='[]'
  local ubuntu_report_references_json
  local apple_report_references_json='[]'
  local cloudimg_enabled=false
  local cloudimg_summary_sha
  local cloudimg_console_sha
  local cloudimg_unixbench_sha
  local cloudimg_candidate_artifacts_json
  local cloudimg_present_artifacts_json
  local cloudimg_optional_artifacts_json=""
  local -a cloudimg_present_artifacts=()

  manifest_generated_at="$(date -u '+%Y-%m-%d %H:%M:%S +00:00:00')"
  script_sha="$(sha256_artifact "scripts/run-uvm-stack-validation.sh")"
  focused_gate_sha="$(sha256_artifact "ci/check-generated-benchmark-artifacts.sh")"
  wave3_evidence_test_sha="$(sha256_artifact "cmd/uhostd/tests/wave3_evidence.rs")"
  host_generated_at="$(extract_report_generated_at "$OUT_DIR/host-validation.md")"
  ubuntu_generated_at="$(extract_report_generated_at "$OUT_DIR/ubuntu-validation.md")"
  apple_generated_at="$(extract_report_generated_at "$OUT_DIR/apple-validation.md")"

  host_sha="$(sha256_artifact "$OUT_DIR/host-validation.md")"
  ubuntu_sha="$(sha256_artifact "$OUT_DIR/ubuntu-validation.md")"
  apple_sha="$(sha256_artifact "$OUT_DIR/apple-validation.md")"
  installer_sha="$(sha256_artifact "$OUT_DIR/ubuntu-26.04-installer-boot-witness.json")"
  disk_sha="$(sha256_artifact "$OUT_DIR/ubuntu-26.04-disk-boot-witness.json")"
  native_sha="$(sha256_artifact "$OUT_DIR/uvm-native-guest-control.json")"
  qemu_summary_sha="$(sha256_artifact "$OUT_DIR/qemu-tcg-bios-ubuntu-26.04-probe.json")"
  qemu_raw_sha="$(sha256_artifact "$OUT_DIR/qemu-tcg-bios-ubuntu-26.04-probe.raw.log")"
  qemu_text_sha="$(sha256_artifact "$OUT_DIR/qemu-tcg-bios-ubuntu-26.04-probe.log")"
  qemu_kernel_sha="$(sha256_artifact "$OUT_DIR/qemu-tcg-kernel-ubuntu-26.04-probe.log")"
  qemu_probe_evidence_references_json="$(json_array_of_strings \
    "docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.raw.log" \
    "docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.log" \
    "docs/benchmarks/generated/qemu-tcg-kernel-ubuntu-26.04-probe.log")"
  ubuntu_report_references_json="$(json_array_of_strings \
    "docs/benchmarks/generated/ubuntu-26.04-installer-boot-witness.json" \
    "docs/benchmarks/generated/ubuntu-26.04-disk-boot-witness.json" \
    "docs/benchmarks/generated/uvm-native-guest-control.json" \
    "docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.raw.log" \
    "docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.log" \
    "docs/benchmarks/generated/qemu-tcg-kernel-ubuntu-26.04-probe.log")"

  cloudimg_candidate_artifacts_json='["docs/benchmarks/generated/qemu-tcg-cloudimg-guest-control.json", "docs/benchmarks/generated/qemu-tcg-cloudimg-console.log", "docs/benchmarks/generated/qemu-tcg-cloudimg-unixbench.log"]'
  if [ "$RUN_CLOUDIMG_GUEST_CONTROL" = "1" ]; then
    local -a cloudimg_references=("docs/benchmarks/generated/qemu-tcg-cloudimg-console.log")
    local cloudimg_references_json
    local cloudimg_unixbench_artifact_json=""

    cloudimg_enabled=true
    cloudimg_summary_sha="$(sha256_artifact "$CLOUDIMG_SUMMARY_PATH")"
    cloudimg_console_sha="$(sha256_artifact "$CLOUDIMG_CONSOLE_LOG_PATH")"
    cloudimg_present_artifacts+=("docs/benchmarks/generated/qemu-tcg-cloudimg-guest-control.json")
    cloudimg_present_artifacts+=("docs/benchmarks/generated/qemu-tcg-cloudimg-console.log")
    if [ -f "$CLOUDIMG_UNIXBENCH_LOG_PATH" ]; then
      cloudimg_unixbench_sha="$(sha256_artifact "$CLOUDIMG_UNIXBENCH_LOG_PATH")"
      cloudimg_present_artifacts+=("docs/benchmarks/generated/qemu-tcg-cloudimg-unixbench.log")
      cloudimg_references+=("docs/benchmarks/generated/qemu-tcg-cloudimg-unixbench.log")
      cloudimg_unixbench_artifact_json=$(cat <<EOF
,
    {
      "path": "docs/benchmarks/generated/qemu-tcg-cloudimg-unixbench.log",
      "kind": "qemu_cloudimg_unixbench_log",
      "evidence_class": "machine_verifiable",
      "sha256": "$cloudimg_unixbench_sha"
    }
EOF
)
    fi
    cloudimg_references_json="$(json_array_of_strings "${cloudimg_references[@]}")"
    cloudimg_optional_artifacts_json=$(cat <<EOF
,
    {
      "path": "docs/benchmarks/generated/qemu-tcg-cloudimg-guest-control.json",
      "kind": "qemu_cloudimg_guest_control_summary",
      "evidence_class": "derived_summary",
      "sha256": "$cloudimg_summary_sha",
      "reference_coverage": "complete",
      "references": $cloudimg_references_json
    },
    {
      "path": "docs/benchmarks/generated/qemu-tcg-cloudimg-console.log",
      "kind": "qemu_cloudimg_console_log",
      "evidence_class": "machine_verifiable",
      "sha256": "$cloudimg_console_sha"
    }$cloudimg_unixbench_artifact_json
EOF
)
  fi
  cloudimg_present_artifacts_json="$(json_array_of_strings "${cloudimg_present_artifacts[@]}")"

  cat > "$MANIFEST_PATH" <<EOF
{
  "schema_version": 3,
  "bundle": "wave3-core-generated-benchmark-evidence",
  "generated_at": "$manifest_generated_at",
  "generator": {
    "script": "scripts/run-uvm-stack-validation.sh",
    "script_sha256": "$script_sha",
    "command": "bash scripts/run-uvm-stack-validation.sh",
    "steps": [
      "cargo test -p uhost-uvm --lib",
      "cargo run -p uhost-uvm --example uvm_validation_report -- host",
      "cargo run -p uhost-uvm --example uvm_validation_report -- ubuntu",
      "cargo run -p uhost-uvm --example uvm_validation_report -- apple",
      "bash scripts/run-uvm-boot-witness.sh",
      "bash scripts/run-uvm-native-guest-control.sh",
      "bash scripts/run-qemu-tcg-boot-probe.sh"
    ],
    "optional_steps": [
      {
        "command": "bash scripts/run-qemu-tcg-cloudimg-guest-control.sh",
        "activation_env": "UHOST_RUN_CLOUDIMG_GUEST_CONTROL",
        "activation_value": "1",
        "enabled": $cloudimg_enabled
      }
    ],
    "generated_directory": "docs/benchmarks/generated",
    "directory_inventory": "exact_manifest_paths",
    "optional_artifact_groups": [
      {
        "name": "qemu_tcg_cloudimg_guest_control",
        "activation_env": "UHOST_RUN_CLOUDIMG_GUEST_CONTROL",
        "activation_value": "1",
        "enabled": $cloudimg_enabled,
        "candidate_artifacts": $cloudimg_candidate_artifacts_json,
        "present_artifacts": $cloudimg_present_artifacts_json
      }
    ]
  },
  "verification": {
    "focused_gate": {
      "path": "ci/check-generated-benchmark-artifacts.sh",
      "sha256": "$focused_gate_sha"
    },
    "wave3_evidence_test": {
      "path": "cmd/uhostd/tests/wave3_evidence.rs",
      "test_name": "wave3_generated_benchmark_artifacts_are_present_and_coherent",
      "sha256": "$wave3_evidence_test_sha"
    }
  },
  "artifacts": [
    {
      "path": "docs/benchmarks/generated/host-validation.md",
      "kind": "validation_report",
      "target": "host",
      "generated_at": "$host_generated_at",
      "sha256": "$host_sha",
      "evidence_class": "derived_summary",
      "reference_coverage": "none",
      "references": $host_report_references_json
    },
    {
      "path": "docs/benchmarks/generated/ubuntu-validation.md",
      "kind": "validation_report",
      "target": "ubuntu_22_04_vm",
      "generated_at": "$ubuntu_generated_at",
      "sha256": "$ubuntu_sha",
      "evidence_class": "derived_summary",
      "reference_coverage": "partial",
      "references": $ubuntu_report_references_json
    },
    {
      "path": "docs/benchmarks/generated/apple-validation.md",
      "kind": "validation_report",
      "target": "apple_mac_studio_m1_pro_sim",
      "generated_at": "$apple_generated_at",
      "sha256": "$apple_sha",
      "evidence_class": "derived_summary",
      "reference_coverage": "none",
      "references": $apple_report_references_json
    },
    {
      "path": "docs/benchmarks/generated/ubuntu-26.04-installer-boot-witness.json",
      "kind": "boot_witness",
      "evidence_class": "machine_verifiable",
      "sha256": "$installer_sha"
    },
    {
      "path": "docs/benchmarks/generated/ubuntu-26.04-disk-boot-witness.json",
      "kind": "boot_witness",
      "evidence_class": "machine_verifiable",
      "sha256": "$disk_sha"
    },
    {
      "path": "docs/benchmarks/generated/uvm-native-guest-control.json",
      "kind": "native_guest_control",
      "evidence_class": "machine_verifiable",
      "sha256": "$native_sha"
    },
    {
      "path": "docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.json",
      "kind": "qemu_probe_summary",
      "evidence_class": "derived_summary",
      "sha256": "$qemu_summary_sha",
      "reference_coverage": "complete",
      "references": $qemu_probe_evidence_references_json
    },
    {
      "path": "docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.raw.log",
      "kind": "qemu_probe_raw_log",
      "evidence_class": "machine_verifiable",
      "sha256": "$qemu_raw_sha"
    },
    {
      "path": "docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.log",
      "kind": "qemu_probe_text_log",
      "evidence_class": "machine_verifiable",
      "sha256": "$qemu_text_sha"
    },
    {
      "path": "docs/benchmarks/generated/qemu-tcg-kernel-ubuntu-26.04-probe.log",
      "kind": "qemu_probe_kernel_log",
      "evidence_class": "machine_verifiable",
      "sha256": "$qemu_kernel_sha"
    }$cloudimg_optional_artifacts_json
  ]
}
EOF

  printf 'generated %s\n' "$MANIFEST_PATH"
}

cleanup_manifest_excluded_artifacts

if [ "$MANIFEST_ONLY" = "1" ]; then
  printf '==> emitting bounded validation manifest from existing artifacts\n'
  emit_validation_manifest
  printf '==> completed manifest-only UVM stack validation refresh\n'
  exit 0
fi

printf '==> formatting and compiling focused UVM stack artifacts\n'
cargo test -p uhost-uvm --lib

printf '==> probing QEMU availability\n'
if command -v qemu-system-x86_64 >/dev/null 2>&1; then
  qemu-system-x86_64 --version
else
  echo 'qemu-system-x86_64: unavailable in current environment'
fi
if command -v qemu-system-aarch64 >/dev/null 2>&1; then
  qemu-system-aarch64 --version
else
  echo 'qemu-system-aarch64: unavailable in current environment'
fi

printf '==> generating validation reports\n'
for target in "${TARGETS[@]}"; do
  cargo run -p uhost-uvm --example uvm_validation_report -- "$target" > "$OUT_DIR/${target}-validation.md"
  printf 'generated %s\n' "$OUT_DIR/${target}-validation.md"
done

printf '==> generating boot witness artifacts\n'
bash scripts/run-uvm-boot-witness.sh

printf '==> generating UVM-native guest-control artifact\n'
bash scripts/run-uvm-native-guest-control.sh

printf '==> generating QEMU TCG BIOS boot probe\n'
bash scripts/run-qemu-tcg-boot-probe.sh

if [ "$RUN_CLOUDIMG_GUEST_CONTROL" = "1" ]; then
  printf '==> generating QEMU TCG cloud-image guest-control artifacts\n'
  UHOST_RUN_UNIXBENCH="${UHOST_RUN_UNIXBENCH:-0}" \
    UHOST_KEEP_GUEST_RUNNING="${UHOST_KEEP_GUEST_RUNNING:-0}" \
    bash scripts/run-qemu-tcg-cloudimg-guest-control.sh
fi

printf '==> emitting bounded validation manifest\n'
emit_validation_manifest

printf '==> completed UVM stack validation artifact generation\n'
