#!/bin/sh
set -eu

ISO_URL="https://cdimage.ubuntu.com/ubuntu-server/daily-live/current/resolute-live-server-amd64.iso"
ISO_PATH="tmp/boot-probes/resolute-live-server-amd64.iso"
RAW_LOG="docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.raw.log"
TEXT_LOG="docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.log"
KERNEL_LOG="docs/benchmarks/generated/qemu-tcg-kernel-ubuntu-26.04-probe.log"
SUMMARY_JSON="docs/benchmarks/generated/qemu-tcg-bios-ubuntu-26.04-probe.json"
FIRMWARE="/usr/share/seabios/bios.bin"
KERNEL_PATH="tmp/boot-probes/ubuntu-casper/vmlinuz"
INITRD_PATH="tmp/boot-probes/ubuntu-casper/initrd"

mkdir -p tmp/boot-probes docs/benchmarks/generated

if [ ! -f "$ISO_PATH" ]; then
  echo "==> downloading Ubuntu ISO"
  curl -L --fail --retry 2 -o "$ISO_PATH" "$ISO_URL"
fi

if [ ! -f "$KERNEL_PATH" ] || [ ! -f "$INITRD_PATH" ]; then
  echo "==> extracting installer kernel and initrd"
  mkdir -p tmp/boot-probes/ubuntu-casper
  xorriso -osirrox on -indev "$ISO_PATH" \
    -extract /casper/vmlinuz "$KERNEL_PATH" \
    -extract /casper/initrd "$INITRD_PATH"
fi

echo "==> running QEMU TCG BIOS boot probe"
set +e
timeout 60 script -q -c "/usr/bin/qemu-system-x86_64 -accel tcg -m 2048 -smp 2 -boot d -cdrom '$ISO_PATH' -bios '$FIRMWARE' -nographic -monitor none -no-reboot" "$RAW_LOG"
BIOS_STATUS=$?

echo "==> running QEMU TCG extracted-kernel serial probe"
timeout 200 /usr/bin/qemu-system-x86_64 \
  -accel tcg \
  -m 2048 \
  -smp 2 \
  -kernel "$KERNEL_PATH" \
  -initrd "$INITRD_PATH" \
  -append 'console=ttyS0,115200n8 boot=casper ---' \
  -drive file="$ISO_PATH",media=cdrom,if=ide \
  -nographic \
  -monitor none \
  -no-reboot > "$KERNEL_LOG" 2>&1
KERNEL_STATUS=$?
set -e

perl -pe 's/\e\[[0-9;?]*[ -\/]*[@-~]//g' "$RAW_LOG" > "$TEXT_LOG"

BOOT_MENU=false
INSTALLER_READY=false
KERNEL_BOOT_TEXT=false
KERNEL_INSTALLER_READY=false
CASPER_CDROM_MISMATCH=false
KERNEL_PANIC_DETECTED=false
SYSTEMD_LOGIN_PROMPT_DETECTED=false
USRSPACE_TARGET_DETECTED=false
if grep -Eqi 'GNU GRUB|highlighted entry' "$TEXT_LOG"; then
  BOOT_MENU=true
fi
if grep -Eqi 'Ubuntu|installer|Try or Install|Install Ubuntu|Booting from DVD/CD' "$TEXT_LOG"; then
  INSTALLER_READY=true
fi
if grep -Eqi 'Linux version|VFS: Finished mounting rootfs|clocksource:' "$KERNEL_LOG"; then
  KERNEL_BOOT_TEXT=true
fi
if grep -Eqi 'installer|casper|Mounting root file system|VFS: Finished mounting rootfs' "$KERNEL_LOG"; then
  KERNEL_INSTALLER_READY=true
fi
if grep -qi "can't open /dev/sr0: No medium found" "$KERNEL_LOG"; then
  CASPER_CDROM_MISMATCH=true
fi
if grep -qi 'Kernel panic - not syncing' "$KERNEL_LOG"; then
  KERNEL_PANIC_DETECTED=true
fi
if grep -Eqi 'serial-getty@ttyS0.service|ttyS0$|ubuntu-server ttyS0' "$KERNEL_LOG"; then
  SYSTEMD_LOGIN_PROMPT_DETECTED=true
fi
if grep -Eqi 'Reached target .*getty.target|Reached target .*basic.target|Started .*Cloud-init: Config Stage' "$KERNEL_LOG"; then
  USRSPACE_TARGET_DETECTED=true
fi

cat > "$SUMMARY_JSON" <<JSON
{
  "iso_path": "$ISO_PATH",
  "firmware": "$FIRMWARE",
  "bios_probe_exit_code": $BIOS_STATUS,
  "boot_menu_detected": $BOOT_MENU,
  "bios_installer_strings_detected": $INSTALLER_READY,
  "kernel_probe_exit_code": $KERNEL_STATUS,
  "kernel_boot_text_detected": $KERNEL_BOOT_TEXT,
  "kernel_installer_progress_detected": $KERNEL_INSTALLER_READY,
  "casper_cdrom_mismatch_detected": $CASPER_CDROM_MISMATCH,
  "kernel_panic_detected": $KERNEL_PANIC_DETECTED,
  "userspace_targets_detected": $USRSPACE_TARGET_DETECTED,
  "serial_login_prompt_detected": $SYSTEMD_LOGIN_PROMPT_DETECTED,
  "raw_log": "$RAW_LOG",
  "text_log": "$TEXT_LOG",
  "kernel_log": "$KERNEL_LOG"
}
JSON

echo "==> summary written to $SUMMARY_JSON"
cat "$SUMMARY_JSON"
