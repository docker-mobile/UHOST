#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
if [ -z "${CARGO_TARGET_DIR:-}" ]; then
  exec bash "$REPO_ROOT/scripts/with-disposable-target-dir.sh" uvm-native-guest-control sh "$0" "$@"
fi
cd "$REPO_ROOT"

PATH=/data/home/.cargo/bin:$PATH

OUT_DIR="${UHOST_UVM_NATIVE_GUEST_CONTROL_OUT_DIR:-$REPO_ROOT/docs/benchmarks/generated}"
OUT_JSON="${UHOST_UVM_NATIVE_GUEST_CONTROL_OUT_JSON:-$OUT_DIR/uvm-native-guest-control.json}"
WORK_DIR="${UHOST_UVM_NATIVE_GUEST_CONTROL_WORK_DIR:-$REPO_ROOT/tmp/uvm-native-guest-control}"
DISK_IMAGE="${UHOST_UVM_NATIVE_GUEST_CONTROL_DISK:-$WORK_DIR/ubuntu-nightly-root.raw}"
FIRMWARE_ARTIFACT="${UHOST_UVM_SOFTVM_FIRMWARE_ARTIFACT:-/usr/share/OVMF/OVMF_CODE.fd}"

mkdir -p "$OUT_DIR"
mkdir -p "$WORK_DIR"

if [ ! -f "$DISK_IMAGE" ]; then
  mkdir -p "$(dirname "$DISK_IMAGE")"
  printf '%s\n' 'uhost-softvm-guest-control-disk' > "$DISK_IMAGE"
fi

if [ ! -f "$FIRMWARE_ARTIFACT" ]; then
  printf 'error: firmware artifact not found at %s\n' "$FIRMWARE_ARTIFACT" >&2
  exit 1
fi

UVM_BACKEND=software_dbt cargo run -q -p uhost-uvm-runner -- \
  --session urs_uvm_native_guest_1 \
  --instance uvi_uvm_native_guest_1 \
  --arch x86_64 \
  --vcpu 2 \
  --memory-mb 4096 \
  --firmware uefi_standard \
  --firmware-artifact "$FIRMWARE_ARTIFACT" \
  --disk "$DISK_IMAGE" \
  --boot-device disk \
  --boot-path general_purpose \
  --device-model virtio_balanced \
  --machine-family general_purpose_pci \
  --execution-class balanced \
  --restart-policy on-failure \
  --migration-kind crash_consistent \
  --guest-command 'echo benchmark-start > /var/tmp/workload-state' \
  --guest-command 'cat /var/tmp/workload-state' \
  --guest-command 'ls /var/tmp' \
  --guest-command 'uname -a' \
  --guest-command 'systemctl is-system-running' \
  --guest-command 'cat /var/log/boot.log' \
  --guest-command 'unixbench --summary' \
  --guest-command 'sha256sum /var/log/unixbench/latest.log' \
  --guest-command 'cat /var/log/unixbench/latest.log' \
  --guest-command 'cat /proc/meminfo' \
  > "$OUT_JSON"

echo "==> native guest-control artifact written to $OUT_JSON"
cat "$OUT_JSON"
