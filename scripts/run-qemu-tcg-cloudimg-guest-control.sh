#!/usr/bin/env bash
set -euo pipefail

BASE_IMG_URL="https://cloud-images.ubuntu.com/daily/server/resolute/current/resolute-server-cloudimg-amd64.img"
BASE_IMG_PATH="tmp/cloudimg/resolute-server-cloudimg-amd64.img"
WORK_DIR="tmp/cloudimg-guest-control"
OUT_DIR="docs/benchmarks/generated"
OVERLAY_IMG="$WORK_DIR/resolute-server-cloudimg-amd64-overlay.qcow2"
SEED_ISO="$WORK_DIR/nocloud-seed.iso"
USER_DATA="$WORK_DIR/user-data"
META_DATA="$WORK_DIR/meta-data"
SSH_KEY="$WORK_DIR/id_ed25519"
PID_FILE="$WORK_DIR/qemu.pid"
CONSOLE_LOG="$OUT_DIR/qemu-tcg-cloudimg-console.log"
SUMMARY_JSON="$OUT_DIR/qemu-tcg-cloudimg-guest-control.json"
UNIXBENCH_LOG="$OUT_DIR/qemu-tcg-cloudimg-unixbench.log"
SSH_PORT="${UHOST_SSH_PORT:-2222}"
RUN_UNIXBENCH="${UHOST_RUN_UNIXBENCH:-0}"
KEEP_GUEST_RUNNING="${UHOST_KEEP_GUEST_RUNNING:-0}"

mkdir -p "$WORK_DIR" "$OUT_DIR" tmp/cloudimg

if [ -f "$PID_FILE" ]; then
  old_pid=$(cat "$PID_FILE" 2>/dev/null || true)
  if [ -n "${old_pid:-}" ] && kill -0 "$old_pid" 2>/dev/null; then
    kill "$old_pid" 2>/dev/null || true
    sleep 2
    kill -9 "$old_pid" 2>/dev/null || true
  fi
fi
pkill -f 'qemu-system-x86_64 -accel tcg -m 2048 -smp 2 -drive file=tmp/cloudimg-guest-control/resolute-server-cloudimg-amd64-overlay.qcow2' 2>/dev/null || true
sleep 2

if [ ! -f "$BASE_IMG_PATH" ]; then
  echo "==> downloading Ubuntu cloud image"
  curl -L --fail --retry 2 --continue-at - -o "$BASE_IMG_PATH" "$BASE_IMG_URL"
fi

if [ ! -f "$SSH_KEY" ]; then
  ssh-keygen -q -t ed25519 -N "" -f "$SSH_KEY"
fi
PUBKEY=$(tr -d '\n' < "$SSH_KEY.pub")

cat > "$USER_DATA" <<CLOUDCFG
#cloud-config
users:
  - default
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $PUBKEY
    shell: /bin/bash
ssh_pwauth: false
disable_root: true
package_update: false
runcmd:
  - [ bash, -lc, 'echo uhost-cloud-init-ready > /var/tmp/uhost-cloud-init-ready' ]
final_message: 'uhost cloud-init finished'
CLOUDCFG

cat > "$META_DATA" <<'METADATA'
instance-id: iid-uhost-tcg-cloudimg-01
local-hostname: uhost-tcg-cloudimg
METADATA

rm -f "$SEED_ISO" "$OVERLAY_IMG" "$PID_FILE" "$CONSOLE_LOG" "$SUMMARY_JSON" "$UNIXBENCH_LOG"
xorriso -as mkisofs -volid cidata -joliet -rock -output "$SEED_ISO" "$USER_DATA" "$META_DATA" >/dev/null 2>&1
qemu-img create -q -f qcow2 -F qcow2 -b "$(pwd)/$BASE_IMG_PATH" "$OVERLAY_IMG"
qemu-img resize -q "$OVERLAY_IMG" +24G

cleanup() {
  if [ "$KEEP_GUEST_RUNNING" = "1" ]; then
    return
  fi
  if [ -f "$PID_FILE" ]; then
    pid=$(cat "$PID_FILE" 2>/dev/null || true)
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      sleep 2
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
}
trap cleanup EXIT

/usr/bin/qemu-system-x86_64 \
  -accel tcg \
  -m 2048 \
  -smp 2 \
  -drive file="$OVERLAY_IMG",if=virtio,format=qcow2 \
  -drive file="$SEED_ISO",media=cdrom,if=ide \
  -netdev user,id=n1,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22 \
  -device virtio-net-pci,netdev=n1 \
  -display none \
  -monitor none \
  -serial file:"$CONSOLE_LOG" \
  -no-reboot \
  -daemonize \
  -pidfile "$PID_FILE"

SSH_READY=false
for _ in $(seq 1 90); do
  if ssh -p "$SSH_PORT" \
    -i "$SSH_KEY" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes \
    -o ConnectTimeout=5 \
    ubuntu@127.0.0.1 'echo ssh-ready' >/dev/null 2>&1; then
    SSH_READY=true
    break
  fi
  sleep 5
  if [ -f "$PID_FILE" ] && ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    break
  fi
done

if [ "$SSH_READY" != true ]; then
  echo "SSH did not become ready" >&2
  exit 1
fi

SSH_BASE=(ssh -p "$SSH_PORT" -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 ubuntu@127.0.0.1)

"${SSH_BASE[@]}" 'cloud-init status --wait || true' >/dev/null 2>&1
KERNEL_INFO=$("${SSH_BASE[@]}" 'uname -a' | tr -d '\r\n')
SYSTEM_STATE=$("${SSH_BASE[@]}" 'systemctl is-system-running 2>/dev/null || true' | tr -d '\r')
CLOUD_INIT_MARKER=$("${SSH_BASE[@]}" 'test -f /var/tmp/uhost-cloud-init-ready && printf true || printf false')
SERIAL_LOGIN_PROMPT=false
if grep -Eqi 'ubuntu-server ttyS0|serial-getty@ttyS0.service|login:' "$CONSOLE_LOG"; then
  SERIAL_LOGIN_PROMPT=true
fi

UNIXBENCH_ATTEMPTED=false
UNIXBENCH_SUCCESS=false
UNIXBENCH_STATUS="not_attempted"
if [ "$RUN_UNIXBENCH" = "1" ]; then
  UNIXBENCH_ATTEMPTED=true
  : > "$UNIXBENCH_LOG"
  if "${SSH_BASE[@]}" "sudo bash -lc 'export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y git build-essential perl make'" >> "$UNIXBENCH_LOG" 2>&1; then
    if "${SSH_BASE[@]}" "bash -lc 'rm -rf ~/byte-unixbench && git clone --depth 1 https://github.com/kdlucas/byte-unixbench.git ~/byte-unixbench'" >> "$UNIXBENCH_LOG" 2>&1; then
      if ! "${SSH_BASE[@]}" "bash -lc \"perl -0pi -e 's/void \\\Q(*func)()\\\E;/void (*func)(int);/' ~/byte-unixbench/UnixBench/src/timeit.c && perl -0pi -e 's/void\\s+pipeerr\\(\\);/void pipeerr(int);/; s/void\\s+grunt\\(\\);/void grunt(int);/; s/void\\s+grunt\\(\\)/void grunt(int signum)/; s/void\\s+pipeerr\\(\\)/void pipeerr(int signum)/' ~/byte-unixbench/UnixBench/src/big.c && perl -0pi -e 's/^char \\*getenv\\(\\);\\s*\\n//m' ~/byte-unixbench/UnixBench/src/execl.c && perl -0pi -e 's/Enumeration\\s+Func_1\\s*\\(\\s*\\);/Enumeration Func_1(Capital_Letter, Capital_Letter);/' ~/byte-unixbench/UnixBench/src/dhry_1.c && perl -0pi -e 's/void\\s+stop_count\\(\\);/void stop_count(int);/; s/void\\s+clean_up\\(\\);/void clean_up(int);/; s/void\\s+stop_count\\(void\\)/void stop_count(int signum)/; s/void\\s+clean_up\\(void\\)/void clean_up(int signum)/; s/stop_count\\(\\);/stop_count(0);/g; s/clean_up\\(\\);/clean_up(0);/g' ~/byte-unixbench/UnixBench/src/fstime.c\"" >> "$UNIXBENCH_LOG" 2>&1; then
        UNIXBENCH_STATUS="source_patch_failed"
      elif "${SSH_BASE[@]}" "bash -lc 'cd ~/byte-unixbench/UnixBench && make -j2 && ./Run -i 1 -c 2'" >> "$UNIXBENCH_LOG" 2>&1; then
        UNIXBENCH_SUCCESS=true
        UNIXBENCH_STATUS="succeeded"
      else
        UNIXBENCH_STATUS="run_failed"
      fi
    else
      UNIXBENCH_STATUS="clone_failed"
    fi
  else
    UNIXBENCH_STATUS="dependency_install_failed"
  fi
fi

BASE_IMG_PATH="$BASE_IMG_PATH" \
OVERLAY_IMG="$OVERLAY_IMG" \
SEED_ISO="$SEED_ISO" \
SSH_READY="$SSH_READY" \
SERIAL_LOGIN_PROMPT="$SERIAL_LOGIN_PROMPT" \
CLOUD_INIT_MARKER="$CLOUD_INIT_MARKER" \
SYSTEM_STATE="${SYSTEM_STATE:-unknown}" \
KERNEL_INFO="$KERNEL_INFO" \
UNIXBENCH_ATTEMPTED="$UNIXBENCH_ATTEMPTED" \
UNIXBENCH_SUCCESS="$UNIXBENCH_SUCCESS" \
UNIXBENCH_STATUS="$UNIXBENCH_STATUS" \
SSH_PORT="$SSH_PORT" \
SSH_KEY="$SSH_KEY" \
KEEP_GUEST_RUNNING="$KEEP_GUEST_RUNNING" \
PID_FILE="$PID_FILE" \
CONSOLE_LOG="$CONSOLE_LOG" \
UNIXBENCH_LOG="$UNIXBENCH_LOG" \
perl -MJSON::PP -e '
my %data = (
  base_image => $ENV{BASE_IMG_PATH},
  overlay_image => $ENV{OVERLAY_IMG},
  seed_iso => $ENV{SEED_ISO},
  ssh_ready => $ENV{SSH_READY} eq q(true) ? JSON::PP::true : JSON::PP::false,
  serial_login_prompt_detected => $ENV{SERIAL_LOGIN_PROMPT} eq q(true) ? JSON::PP::true : JSON::PP::false,
  cloud_init_ready_marker => $ENV{CLOUD_INIT_MARKER} eq q(true) ? JSON::PP::true : JSON::PP::false,
  system_state => $ENV{SYSTEM_STATE},
  kernel_info => $ENV{KERNEL_INFO},
  unixbench_attempted => $ENV{UNIXBENCH_ATTEMPTED} eq q(true) ? JSON::PP::true : JSON::PP::false,
  unixbench_success => $ENV{UNIXBENCH_SUCCESS} eq q(true) ? JSON::PP::true : JSON::PP::false,
  unixbench_status => $ENV{UNIXBENCH_STATUS},
  ssh_port => $ENV{SSH_PORT},
  ssh_private_key => $ENV{SSH_KEY},
  keep_guest_running => $ENV{KEEP_GUEST_RUNNING} eq q(1) ? JSON::PP::true : JSON::PP::false,
  pid_file => $ENV{PID_FILE},
  console_log => $ENV{CONSOLE_LOG},
  unixbench_log => $ENV{UNIXBENCH_LOG},
);
print JSON::PP->new->ascii->pretty->encode(\%data);
' > "$SUMMARY_JSON"

echo "==> guest control summary written to $SUMMARY_JSON"
cat "$SUMMARY_JSON"
