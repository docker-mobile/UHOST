#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
if [ -z "${CARGO_TARGET_DIR:-}" ]; then
  exec bash "$REPO_ROOT/scripts/with-disposable-target-dir.sh" uvm-boot-witness sh "$0" "$@"
fi
cd "$REPO_ROOT"

PATH=/data/home/.cargo/bin:$PATH

OUT_DIR="${UHOST_UVM_BOOT_WITNESS_OUT_DIR:-$REPO_ROOT/docs/benchmarks/generated}"
WORK_DIR="${UHOST_UVM_BOOT_WITNESS_WORK_DIR:-$REPO_ROOT/tmp/uvm-boot-witness}"
INSTALLER_DISK="${UHOST_UVM_BOOT_WITNESS_INSTALLER_DISK:-$WORK_DIR/ubuntu-installer.raw}"
INSTALLER_ISO="${UHOST_UVM_BOOT_WITNESS_INSTALLER_ISO:-$WORK_DIR/ubuntu-26.04-installer.iso}"
ROOT_DISK="${UHOST_UVM_BOOT_WITNESS_ROOT_DISK:-$WORK_DIR/ubuntu-26.04-root.raw}"

mkdir -p "$OUT_DIR" "$WORK_DIR"

if [ ! -f "$INSTALLER_DISK" ]; then
  printf '%s\n' 'uhost-softvm-installer-disk' > "$INSTALLER_DISK"
fi
if [ ! -f "$INSTALLER_ISO" ]; then
  printf '%s\n' 'uhost-softvm-installer-iso' > "$INSTALLER_ISO"
fi
if [ ! -f "$ROOT_DISK" ]; then
  printf '%s\n' 'uhost-softvm-root-disk' > "$ROOT_DISK"
fi

echo "==> generating BIOS+ISO installer boot witness"
UVM_BACKEND=software_dbt cargo run -q -p uhost-uvm-runner -- \
  --session urs_boot_installer_1 \
  --instance uvi_boot_installer_1 \
  --arch x86_64 \
  --vcpu 2 \
  --memory-mb 4096 \
  --firmware bios \
  --disk "$INSTALLER_DISK" \
  --cdrom "$INSTALLER_ISO" \
  --boot-device cdrom \
  --boot-path general_purpose \
  --device-model virtio_balanced \
  --machine-family general_purpose_pci \
  --execution-class balanced \
  --restart-policy on-failure \
  --migration-kind crash_consistent \
  --telemetry heartbeat \
  --numa-node 0 \
  > "$OUT_DIR/ubuntu-26.04-installer-boot-witness.json"

echo "==> generating UEFI disk boot witness"
UVM_BACKEND=software_dbt cargo run -q -p uhost-uvm-runner -- \
  --session urs_boot_disk_1 \
  --instance uvi_boot_disk_1 \
  --arch x86_64 \
  --vcpu 2 \
  --memory-mb 4096 \
  --firmware uefi_standard \
  --disk "$ROOT_DISK" \
  --boot-device disk \
  --boot-path general_purpose \
  --device-model virtio_balanced \
  --machine-family general_purpose_pci \
  --execution-class balanced \
  --restart-policy on-failure \
  --migration-kind crash_consistent \
  --telemetry heartbeat \
  --numa-node 0 \
  > "$OUT_DIR/ubuntu-26.04-disk-boot-witness.json"

echo "==> boot witness artifacts written to $OUT_DIR"
