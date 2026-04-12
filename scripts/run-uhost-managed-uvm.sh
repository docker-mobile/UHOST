#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
PATH=/data/home/.cargo/bin:$PATH

WORK_DIR="${UHOST_MANAGED_UVM_WORK_DIR:-$REPO_ROOT/tmp/uhost-managed-uvm}"
LISTEN="${UHOST_MANAGED_UVM_LISTEN:-127.0.0.1:19081}"
NODE_NAME="${UHOST_MANAGED_UVM_NODE_NAME:-managed-uvm-node}"
VM_NAME="${UHOST_MANAGED_UVM_NAME:-ubuntu-26.04-managed}"
GUEST_OS="${UHOST_MANAGED_UVM_GUEST_OS:-ubuntu-26.04}"
ARCH="${UHOST_MANAGED_UVM_ARCH:-x86_64}"
PROJECT_ID="${UHOST_MANAGED_UVM_PROJECT_ID:-prj_aaaaaaaaaaaaaaaaaaaa}"
HOST_NODE_ID="${UHOST_MANAGED_UVM_HOST_NODE_ID:-nod_aaaaaaaaaaaaaaaaaaaa}"
BASE_DISK_IMAGE="${UHOST_MANAGED_UVM_DISK_IMAGE:-$REPO_ROOT/tmp/cloudimg/resolute-server-cloudimg-amd64.img}"
FIRMWARE_ARTIFACT="${UHOST_MANAGED_UVM_FIRMWARE_ARTIFACT:-/usr/share/OVMF/OVMF_CODE.fd}"
RESET_WORK_DIR="${UHOST_MANAGED_UVM_RESET:-1}"

usage() {
  cat <<'EOF'
usage: bash scripts/run-uhost-managed-uvm.sh [options]

Options:
  --work-dir <path>          Working directory for config, state, logs, and env files
  --listen <host:port>       Control-plane listen address (default 127.0.0.1:19081)
  --name <vm-name>           Managed UVM instance name
  --guest-os <family>        Guest OS label (default ubuntu-26.04)
  --disk-image <path>        Local base disk image to copy into the working directory
  --firmware-artifact <uri>  Local firmware artifact path (default /usr/share/OVMF/OVMF_CODE.fd)
  --no-reset                 Reuse the working directory instead of recreating it

This helper brings up a same-host UHost control plane, seeds one software_dbt
managed UVM instance, and writes a shell-friendly session file. The current
managed software_dbt path exposes control-plane access, guest-control
readiness, guest-owned usernet-style NAT, outbound HTTP/HTTPS plus generic
TCP/UDP egress, managed HTTP ingress for the guest web root, and managed TCP
plus UDP ingress. It still does not expose SSH, raw sockets, or a post-start
guest exec API.
EOF
}

while (($# > 0)); do
  case "$1" in
    --work-dir)
      WORK_DIR="$2"
      shift 2
      ;;
    --listen)
      LISTEN="$2"
      shift 2
      ;;
    --name)
      VM_NAME="$2"
      shift 2
      ;;
    --guest-os)
      GUEST_OS="$2"
      shift 2
      ;;
    --disk-image)
      BASE_DISK_IMAGE="$2"
      shift 2
      ;;
    --firmware-artifact)
      FIRMWARE_ARTIFACT="$2"
      shift 2
      ;;
    --no-reset)
      RESET_WORK_DIR=0
      shift
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown argument %s\n\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

STATE_DIR="$WORK_DIR/state"
CONFIG_PATH="$WORK_DIR/all-in-one.toml"
TOKEN_PATH="$WORK_DIR/bootstrap-admin.token"
MASTER_KEY_PATH="$WORK_DIR/master-key.token"
PID_PATH="$WORK_DIR/uhostd.pid"
LOG_PATH="$WORK_DIR/uhostd.log"
SESSION_ENV_PATH="$WORK_DIR/session.env"
SESSION_JSON_PATH="$WORK_DIR/session.json"
RUN_DISK_IMAGE="$WORK_DIR/${VM_NAME//\//-}.qcow2"
RUN_DISK_IMAGE_ABS=
CONTROL_ENDPOINT="http://$LISTEN"
COMPATIBILITY_ROW_ID="ucr_aaaaaaaaaaaaaaaaaaaa"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'error: required command not found: %s\n' "$1" >&2
    exit 1
  fi
}

require_cmd cargo
require_cmd curl
require_cmd jq
require_cmd cp
require_cmd grep

if [ ! -f "$BASE_DISK_IMAGE" ]; then
  printf 'error: base disk image not found at %s\n' "$BASE_DISK_IMAGE" >&2
  exit 1
fi

if [ ! -f "$FIRMWARE_ARTIFACT" ]; then
  printf 'error: firmware artifact not found at %s\n' "$FIRMWARE_ARTIFACT" >&2
  exit 1
fi

stop_existing_control_plane() {
  if [ -f "$PID_PATH" ]; then
    local pid
    pid=$(cat "$PID_PATH")
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      pkill -P "$pid" 2>/dev/null || true
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 50); do
        if ! kill -0 "$pid" 2>/dev/null; then
          break
        fi
        sleep 0.1
      done
      if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null || true
      fi
    fi
    rm -f "$PID_PATH"
  fi
}

write_config() {
  local master_key admin_token
  master_key=$(cat "$MASTER_KEY_PATH")
  admin_token=$(cat "$TOKEN_PATH")
  cat >"$CONFIG_PATH" <<EOF
listen = "$LISTEN"
state_dir = "$STATE_DIR"

[schema]
schema_version = 1
mode = "all_in_one"
node_name = "$NODE_NAME"

[secrets]
master_key = "$master_key"

[security]
bootstrap_admin_token = "$admin_token"
EOF
}

wait_for_healthz() {
  for _ in $(seq 1 600); do
    if curl -fsS "$CONTROL_ENDPOINT/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  printf 'error: uhostd did not become healthy; log: %s\n' "$LOG_PATH" >&2
  stop_existing_control_plane
  exit 1
}

wait_for_runtime_access_contract() {
  local instance_id="$1"
  local contract=""
  for _ in $(seq 1 600); do
    if contract=$(api_json GET "/uvm/instances/$instance_id/resolved-contract" 2>/dev/null); then
      if [ "$(printf '%s' "$contract" | json_field '.runtime_access != null')" = "true" ]; then
        printf '%s' "$contract"
        return 0
      fi
    fi
    sleep 0.2
  done
  if [ -n "$contract" ]; then
    printf '%s' "$contract"
    return 0
  fi
  printf 'error: managed runtime access contract did not materialize; log: %s\n' "$LOG_PATH" >&2
  stop_existing_control_plane
  exit 1
}

start_control_plane() {
  cargo build -q -p uhostd -p uhostctl -p uhost-uvm-runner
  nohup "$REPO_ROOT/target/debug/uhostd" --config "$CONFIG_PATH" >"$LOG_PATH" 2>&1 &
  echo "$!" >"$PID_PATH"
  wait_for_healthz
}

json_field() {
  jq -r "$1"
}

api_json() {
  local method="$1"
  local path="$2"
  local payload="${3:-}"
  if [ -n "$payload" ]; then
    curl -fsS -X "$method" \
      -H "Authorization: Bearer $(cat "$TOKEN_PATH")" \
      -H "X-UHost-Admin-Token: $(cat "$TOKEN_PATH")" \
      -H "Content-Type: application/json" \
      --data "$payload" \
      "$CONTROL_ENDPOINT$path"
  else
    curl -fsS -X "$method" \
      -H "Authorization: Bearer $(cat "$TOKEN_PATH")" \
      -H "X-UHost-Admin-Token: $(cat "$TOKEN_PATH")" \
      "$CONTROL_ENDPOINT$path"
  fi
}

detect_container_restricted() {
  if [ -f "/.dockerenv" ]; then
    return 0
  fi
  if [ -r /proc/1/cgroup ] && grep -Eq 'docker|kubepods|containerd' /proc/1/cgroup; then
    return 0
  fi
  return 1
}

ensure_dev_compatibility_bridge() {
  local host_class="$1"
  local compatibility_path="$STATE_DIR/uvm-image/compatibility.json"
  local temp_path="$compatibility_path.tmp"

  jq \
    --arg host_class "$host_class" \
    --arg row_id "$COMPATIBILITY_ROW_ID" \
    '
      def software_row:
        .records
        | to_entries
        | map(
            select(
              (.value.deleted | not)
              and .value.value.accelerator_backend == "software_dbt"
              and .value.value.guest_architecture == "x86_64"
              and .value.value.machine_family == "general_purpose_pci"
              and .value.value.guest_profile == "linux_standard"
              and .value.value.claim_tier == "compatible"
            )
          )
        | first;
      def variant_key($row):
        ($row.host_class + ":" + $row.region + ":" + $row.cell + ":" + $row.host_family + ":" + $row.guest_architecture + ":" + $row.accelerator_backend + ":" + $row.machine_family + ":" + $row.guest_profile + ":" + $row.claim_tier);
      if (.records
          | to_entries
          | any(
              (.value.deleted | not)
              and .value.value.host_class == $host_class
              and .value.value.accelerator_backend == "software_dbt"
              and .value.value.guest_architecture == "x86_64"
              and .value.value.machine_family == "general_purpose_pci"
              and .value.value.guest_profile == "linux_standard"
              and .value.value.claim_tier == "compatible"
            )) then
        .
      else
        (software_row) as $base
        | if $base == null then
            error("missing base software_dbt compatibility row")
          else
            ($base.value.value
              | .id = $row_id
              | .host_class = $host_class
              | .region = "global"
              | .cell = "global"
              | .notes = ("Managed dev compatibility bridge for host_class " + $host_class)
            ) as $row
            | .records[variant_key($row)] = {
                "version": 1,
                "updated_at": $base.value.updated_at,
                "deleted": false,
                "value": $row
              }
          end
      end
    ' \
    "$compatibility_path" >"$temp_path"
  mv "$temp_path" "$compatibility_path"
}

if [ "$RESET_WORK_DIR" = "1" ]; then
  stop_existing_control_plane
  rm -rf "$WORK_DIR"
fi

mkdir -p "$WORK_DIR"
mkdir -p "$STATE_DIR"

cargo run -q -p uhostctl -- token generate --bytes 32 >"$MASTER_KEY_PATH"
cargo run -q -p uhostctl -- token generate >"$TOKEN_PATH"
cp --reflink=auto "$BASE_DISK_IMAGE" "$RUN_DISK_IMAGE"
RUN_DISK_IMAGE_ABS=$(realpath "$RUN_DISK_IMAGE")
write_config
stop_existing_control_plane
start_control_plane

if detect_container_restricted; then
  HOST_EVIDENCE_MODE="container_restricted"
  CONTAINER_RESTRICTED=true
  HOST_CLASS="linux_container_restricted"
else
  HOST_EVIDENCE_MODE="direct_host"
  CONTAINER_RESTRICTED=false
  HOST_CLASS="linux_bare_metal"
fi

ensure_dev_compatibility_bridge "$HOST_CLASS"
stop_existing_control_plane
start_control_plane

NODE_CAPABILITY_JSON=$(jq -n \
  --arg node_id "$HOST_NODE_ID" \
  --arg arch "$ARCH" \
  --arg host_evidence_mode "$HOST_EVIDENCE_MODE" \
  --argjson container_restricted "$CONTAINER_RESTRICTED" \
  '{
    node_id: $node_id,
    host_platform: "linux",
    architecture: $arch,
    accelerator_backends: ["software_dbt"],
    max_vcpu: 8,
    max_memory_mb: 16384,
    numa_nodes: 1,
    supports_secure_boot: false,
    supports_live_migration: false,
    supports_pci_passthrough: false,
    software_runner_supported: true,
    container_restricted: $container_restricted,
    host_evidence_mode: $host_evidence_mode
  }')
NODE_CAPABILITY_RESPONSE=$(api_json POST /uvm/node-capabilities "$NODE_CAPABILITY_JSON")
CAPABILITY_ID=$(printf '%s' "$NODE_CAPABILITY_RESPONSE" | json_field '.id')

DEVICE_PROFILE_RESPONSE=$(api_json POST /uvm/device-profiles \
  '{"name":"dev-virtio-balanced","legacy_devices":["pit","rtc","ioapic"],"modern_devices":["virtio-net","virtio-block","virtio-rng"],"passthrough_enabled":false}')
DEVICE_PROFILE_ID=$(printf '%s' "$DEVICE_PROFILE_RESPONSE" | json_field '.id')

FIRMWARE_RESPONSE=$(api_json POST /uvm/firmware-bundles \
  "$(jq -n \
    --arg artifact_uri "file://$FIRMWARE_ARTIFACT" \
    --arg arch "$ARCH" \
    '{
      name: "ovmf-dev",
      architecture: $arch,
      firmware_profile: "uefi_standard",
      artifact_uri: $artifact_uri,
      secure_boot_capable: false,
      verified: true
    }')")
FIRMWARE_ID=$(printf '%s' "$FIRMWARE_RESPONSE" | json_field '.id')

IMAGE_RESPONSE=$(api_json POST /uvm/images \
  "$(jq -n \
    --arg source_uri "file://$RUN_DISK_IMAGE_ABS" \
    --arg guest_os "$GUEST_OS" \
    --arg arch "$ARCH" \
    '{
      source_kind: "qcow2",
      source_uri: $source_uri,
      guest_os: $guest_os,
      architecture: $arch,
      signature_attestation: "dev-local-signature",
      provenance_attestation: "dev-local-provenance"
    }')")
IMAGE_ID=$(printf '%s' "$IMAGE_RESPONSE" | json_field '.id')

api_json POST "/uvm/images/$IMAGE_ID/verify" \
  '{"require_signature":true,"require_provenance":true}' >/dev/null

api_json POST "/uvm/images/$IMAGE_ID/promote" \
  "$(jq -n --arg host_class "$HOST_CLASS" '{channel:"stable",host_class:$host_class}')" >/dev/null

TEMPLATE_RESPONSE=$(api_json POST /uvm/templates \
  "$(jq -n \
    --arg device_profile "$DEVICE_PROFILE_ID" \
    --arg arch "$ARCH" \
    '{
      name: "dev-managed-template",
      architecture: $arch,
      vcpu: 2,
      memory_mb: 2048,
      cpu_topology: "balanced",
      numa_policy: "preferred_local",
      firmware_profile: "uefi_standard",
      device_profile: $device_profile,
      migration_policy: "cold_only",
      machine_family: "general_purpose_pci",
      guest_profile: "linux_standard",
      apple_guest_allowed: false
    }')")
TEMPLATE_ID=$(printf '%s' "$TEMPLATE_RESPONSE" | json_field '.id')

INSTANCE_RESPONSE=$(api_json POST /uvm/instances \
  "$(jq -n \
    --arg project_id "$PROJECT_ID" \
    --arg name "$VM_NAME" \
    --arg template_id "$TEMPLATE_ID" \
    --arg boot_image_id "$IMAGE_ID" \
    --arg guest_os "$GUEST_OS" \
    --arg host_node_id "$HOST_NODE_ID" \
    '{
      project_id: $project_id,
      name: $name,
      template_id: $template_id,
      boot_image_id: $boot_image_id,
      guest_os: $guest_os,
      host_node_id: $host_node_id
    }')")
INSTANCE_ID=$(printf '%s' "$INSTANCE_RESPONSE" | json_field '.id')

RUNTIME_SESSION_PAGE=$(api_json GET "/uvm/instances/$INSTANCE_ID/runtime-sessions")
RUNTIME_SESSION_ID=$(printf '%s' "$RUNTIME_SESSION_PAGE" | jq -r '
  if type == "array" then
    .[0].id // ""
  else
    .items[0].id // ""
  end
')
if [ -z "$RUNTIME_SESSION_ID" ]; then
  RUNTIME_RESPONSE=$(api_json POST /uvm/runtime/instances \
    "$(jq -n \
      --arg instance_id "$INSTANCE_ID" \
      --arg node_id "$HOST_NODE_ID" \
      --arg capability_id "$CAPABILITY_ID" \
      --arg arch "$ARCH" \
      --arg guest_os "$GUEST_OS" \
      --arg disk_image "file://$RUN_DISK_IMAGE_ABS" \
      '{
        instance_id: $instance_id,
        node_id: $node_id,
        capability_id: $capability_id,
        guest_architecture: $arch,
        guest_os: $guest_os,
        disk_image: $disk_image,
        vcpu: 2,
        memory_mb: 2048,
        firmware_profile: "uefi_standard",
        cpu_topology: "balanced",
        numa_policy: "preferred_local",
        migration_policy: "cold_only",
        require_secure_boot: false,
        requires_live_migration: false,
        restart_policy: "on-failure",
        max_restarts: 2,
        isolation_profile: "platform_default"
      }')")
  RUNTIME_SESSION_ID=$(printf '%s' "$RUNTIME_RESPONSE" | json_field '.id')
fi

api_json POST "/uvm/instances/$INSTANCE_ID/start" '{}' >/dev/null
api_json POST "/uvm/runtime/instances/$RUNTIME_SESSION_ID/start" '{}' >/dev/null
RESOLVED_CONTRACT=$(wait_for_runtime_access_contract "$INSTANCE_ID")
ACCESS_NETWORK_MODE=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.network_mode // "guest_control_only"')
ACCESS_INTERNET_NAT=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.internet_nat // false')
ACCESS_SSH_AVAILABLE=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.ssh_available // false')
ACCESS_GUEST_EXEC_AVAILABLE=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.guest_exec_route_available // false')
ACCESS_EGRESS_TRANSPORT=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.egress_transport // ""')
ACCESS_INGRESS_TRANSPORT=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.ingress_transport // ""')
ACCESS_INGRESS_HTTP_READY=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.ingress_http_ready // false')
ACCESS_INGRESS_HTTP_BIND=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.ingress_http_bind // ""')
ACCESS_INGRESS_HTTP_URL=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.ingress_http_url // ""')
ACCESS_INGRESS_TCP_READY=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.ingress_tcp_ready // false')
ACCESS_INGRESS_TCP_BIND=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.ingress_tcp_bind // ""')
ACCESS_INGRESS_TCP_SERVICE=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.ingress_tcp_service // ""')
ACCESS_INGRESS_UDP_READY=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.ingress_udp_ready // false')
ACCESS_INGRESS_UDP_BIND=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.ingress_udp_bind // ""')
ACCESS_INGRESS_UDP_SERVICE=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.ingress_udp_service // ""')
ACCESS_GUEST_WEB_ROOT=$(printf '%s' "$RESOLVED_CONTRACT" | json_field '.runtime_access.guest_web_root // "/var/www"')
ACCESS_INGRESS_TCP_HOST=
ACCESS_INGRESS_TCP_PORT=
ACCESS_INGRESS_UDP_HOST=
ACCESS_INGRESS_UDP_PORT=
if [ -n "$ACCESS_INGRESS_TCP_BIND" ]; then
  ACCESS_INGRESS_TCP_HOST=${ACCESS_INGRESS_TCP_BIND%:*}
  ACCESS_INGRESS_TCP_PORT=${ACCESS_INGRESS_TCP_BIND##*:}
fi
if [ -n "$ACCESS_INGRESS_UDP_BIND" ]; then
  ACCESS_INGRESS_UDP_HOST=${ACCESS_INGRESS_UDP_BIND%:*}
  ACCESS_INGRESS_UDP_PORT=${ACCESS_INGRESS_UDP_BIND##*:}
fi

cat >"$SESSION_ENV_PATH" <<EOF
export UHOST_CONTROL_ENDPOINT=$CONTROL_ENDPOINT
export UHOSTCTL_ADMIN_TOKEN=$(cat "$TOKEN_PATH")
export UHOST_BOOTSTRAP_ADMIN_TOKEN=$(cat "$TOKEN_PATH")
export UHOST_MANAGED_UVM_WORK_DIR=$WORK_DIR
export UHOST_MANAGED_UVM_CONFIG=$CONFIG_PATH
export UHOST_MANAGED_UVM_STATE_DIR=$STATE_DIR
export UHOST_MANAGED_UVM_LOG=$LOG_PATH
export UHOST_MANAGED_UVM_PID=$(cat "$PID_PATH")
export UHOST_MANAGED_UVM_HOST_CLASS=$HOST_CLASS
export UHOST_MANAGED_UVM_NETWORK_MODE=$ACCESS_NETWORK_MODE
export UHOST_MANAGED_UVM_INTERNET_NAT=$ACCESS_INTERNET_NAT
export UHOST_MANAGED_UVM_SSH_AVAILABLE=$ACCESS_SSH_AVAILABLE
export UHOST_MANAGED_UVM_GUEST_EXEC_AVAILABLE=$ACCESS_GUEST_EXEC_AVAILABLE
export UHOST_MANAGED_UVM_EGRESS_TRANSPORT=$ACCESS_EGRESS_TRANSPORT
export UHOST_MANAGED_UVM_INGRESS_TRANSPORT=$ACCESS_INGRESS_TRANSPORT
export UHOST_MANAGED_UVM_INGRESS_HTTP_READY=$ACCESS_INGRESS_HTTP_READY
export UHOST_MANAGED_UVM_INGRESS_HTTP_BIND=$ACCESS_INGRESS_HTTP_BIND
export UHOST_MANAGED_UVM_INGRESS_HTTP_URL=$ACCESS_INGRESS_HTTP_URL
export UHOST_MANAGED_UVM_INGRESS_TCP_READY=$ACCESS_INGRESS_TCP_READY
export UHOST_MANAGED_UVM_INGRESS_TCP_BIND=$ACCESS_INGRESS_TCP_BIND
export UHOST_MANAGED_UVM_INGRESS_TCP_SERVICE=$ACCESS_INGRESS_TCP_SERVICE
export UHOST_MANAGED_UVM_INGRESS_TCP_HOST=$ACCESS_INGRESS_TCP_HOST
export UHOST_MANAGED_UVM_INGRESS_TCP_PORT=$ACCESS_INGRESS_TCP_PORT
export UHOST_MANAGED_UVM_INGRESS_UDP_READY=$ACCESS_INGRESS_UDP_READY
export UHOST_MANAGED_UVM_INGRESS_UDP_BIND=$ACCESS_INGRESS_UDP_BIND
export UHOST_MANAGED_UVM_INGRESS_UDP_SERVICE=$ACCESS_INGRESS_UDP_SERVICE
export UHOST_MANAGED_UVM_INGRESS_UDP_HOST=$ACCESS_INGRESS_UDP_HOST
export UHOST_MANAGED_UVM_INGRESS_UDP_PORT=$ACCESS_INGRESS_UDP_PORT
export UHOST_MANAGED_UVM_GUEST_WEB_ROOT=$ACCESS_GUEST_WEB_ROOT
export UHOST_MANAGED_UVM_CAPABILITY_ID=$CAPABILITY_ID
export UHOST_MANAGED_UVM_DEVICE_PROFILE_ID=$DEVICE_PROFILE_ID
export UHOST_MANAGED_UVM_FIRMWARE_ID=$FIRMWARE_ID
export UHOST_MANAGED_UVM_IMAGE_ID=$IMAGE_ID
export UHOST_MANAGED_UVM_TEMPLATE_ID=$TEMPLATE_ID
export UHOST_MANAGED_UVM_INSTANCE_ID=$INSTANCE_ID
export UHOST_MANAGED_UVM_RUNTIME_SESSION_ID=$RUNTIME_SESSION_ID
EOF

jq -n \
  --arg endpoint "$CONTROL_ENDPOINT" \
  --arg work_dir "$WORK_DIR" \
  --arg config_path "$CONFIG_PATH" \
  --arg state_dir "$STATE_DIR" \
  --arg log_path "$LOG_PATH" \
  --arg pid "$(cat "$PID_PATH")" \
  --arg host_class "$HOST_CLASS" \
  --arg network_mode "$ACCESS_NETWORK_MODE" \
  --argjson internet_nat "$ACCESS_INTERNET_NAT" \
  --argjson ssh_available "$ACCESS_SSH_AVAILABLE" \
  --argjson guest_exec_available "$ACCESS_GUEST_EXEC_AVAILABLE" \
  --arg egress_transport "$ACCESS_EGRESS_TRANSPORT" \
  --arg ingress_transport "$ACCESS_INGRESS_TRANSPORT" \
  --argjson ingress_http_ready "$ACCESS_INGRESS_HTTP_READY" \
  --arg ingress_http_bind "$ACCESS_INGRESS_HTTP_BIND" \
  --arg ingress_http_url "$ACCESS_INGRESS_HTTP_URL" \
  --argjson ingress_tcp_ready "$ACCESS_INGRESS_TCP_READY" \
  --arg ingress_tcp_bind "$ACCESS_INGRESS_TCP_BIND" \
  --arg ingress_tcp_service "$ACCESS_INGRESS_TCP_SERVICE" \
  --argjson ingress_udp_ready "$ACCESS_INGRESS_UDP_READY" \
  --arg ingress_udp_bind "$ACCESS_INGRESS_UDP_BIND" \
  --arg ingress_udp_service "$ACCESS_INGRESS_UDP_SERVICE" \
  --arg guest_web_root "$ACCESS_GUEST_WEB_ROOT" \
  --arg capability_id "$CAPABILITY_ID" \
  --arg device_profile_id "$DEVICE_PROFILE_ID" \
  --arg firmware_id "$FIRMWARE_ID" \
  --arg image_id "$IMAGE_ID" \
  --arg template_id "$TEMPLATE_ID" \
  --arg instance_id "$INSTANCE_ID" \
  --arg runtime_session_id "$RUNTIME_SESSION_ID" \
  '{
    endpoint: $endpoint,
    work_dir: $work_dir,
    config_path: $config_path,
    state_dir: $state_dir,
    log_path: $log_path,
    pid: $pid,
    host_class: $host_class,
    access: {
      network_mode: $network_mode,
      internet_nat: $internet_nat,
      ssh_available: $ssh_available,
      guest_exec_route_available: $guest_exec_available,
      egress_transport: $egress_transport,
      ingress_transport: $ingress_transport,
      ingress_http_ready: $ingress_http_ready,
      ingress_http_bind: ($ingress_http_bind | select(length > 0)),
      ingress_http_url: ($ingress_http_url | select(length > 0)),
      ingress_tcp_ready: $ingress_tcp_ready,
      ingress_tcp_bind: ($ingress_tcp_bind | select(length > 0)),
      ingress_tcp_service: ($ingress_tcp_service | select(length > 0)),
      ingress_udp_ready: $ingress_udp_ready,
      ingress_udp_bind: ($ingress_udp_bind | select(length > 0)),
      ingress_udp_service: ($ingress_udp_service | select(length > 0)),
      guest_web_root: $guest_web_root
    },
    ids: {
      capability_id: $capability_id,
      device_profile_id: $device_profile_id,
      firmware_id: $firmware_id,
      image_id: $image_id,
      template_id: $template_id,
      instance_id: $instance_id,
      runtime_session_id: $runtime_session_id
    }
  }' >"$SESSION_JSON_PATH"

printf '\nUHost managed UVM is running.\n\n'
printf 'Endpoint:          %s\n' "$CONTROL_ENDPOINT"
printf 'Config:            %s\n' "$CONFIG_PATH"
printf 'State:             %s\n' "$STATE_DIR"
printf 'Log:               %s\n' "$LOG_PATH"
printf 'Session env:       %s\n' "$SESSION_ENV_PATH"
printf 'Session summary:   %s\n' "$SESSION_JSON_PATH"
printf '\nAccess:\n'
printf '  Network mode:    %s\n' "$ACCESS_NETWORK_MODE"
printf '  Internet via NAT: %s\n' "$ACCESS_INTERNET_NAT"
printf '  SSH exposed:     %s\n' "$ACCESS_SSH_AVAILABLE"
printf '  Guest exec API:  %s\n' "$ACCESS_GUEST_EXEC_AVAILABLE"
printf '  Egress relay:    %s\n' "${ACCESS_EGRESS_TRANSPORT:-unavailable}"
printf '  Ingress relay:   %s\n' "${ACCESS_INGRESS_TRANSPORT:-unavailable}"
printf '  HTTP ingress:    %s\n' "$ACCESS_INGRESS_HTTP_READY"
if [ -n "$ACCESS_INGRESS_HTTP_BIND" ]; then
  printf '  HTTP bind:       %s\n' "$ACCESS_INGRESS_HTTP_BIND"
fi
if [ -n "$ACCESS_INGRESS_HTTP_URL" ]; then
  printf '  HTTP URL:        %s\n' "$ACCESS_INGRESS_HTTP_URL"
  printf '  Guest web root:  %s\n' "$ACCESS_GUEST_WEB_ROOT"
fi
printf '  TCP ingress:     %s\n' "$ACCESS_INGRESS_TCP_READY"
if [ -n "$ACCESS_INGRESS_TCP_BIND" ]; then
  printf '  TCP bind:        %s\n' "$ACCESS_INGRESS_TCP_BIND"
fi
if [ -n "$ACCESS_INGRESS_TCP_SERVICE" ]; then
  printf '  TCP service:     %s\n' "$ACCESS_INGRESS_TCP_SERVICE"
fi
printf '  UDP ingress:     %s\n' "$ACCESS_INGRESS_UDP_READY"
if [ -n "$ACCESS_INGRESS_UDP_BIND" ]; then
  printf '  UDP bind:        %s\n' "$ACCESS_INGRESS_UDP_BIND"
fi
if [ -n "$ACCESS_INGRESS_UDP_SERVICE" ]; then
  printf '  UDP service:     %s\n' "$ACCESS_INGRESS_UDP_SERVICE"
fi
printf '\nUse it:\n'
printf '  source %s\n' "$SESSION_ENV_PATH"
printf '  curl -fsS -H "Authorization: Bearer $UHOSTCTL_ADMIN_TOKEN" -H "X-UHost-Admin-Token: $UHOSTCTL_ADMIN_TOKEN" "$UHOST_CONTROL_ENDPOINT/uvm/instances/$UHOST_MANAGED_UVM_INSTANCE_ID/resolved-contract" | jq\n'
if [ -n "$ACCESS_INGRESS_HTTP_URL" ]; then
  printf '  curl -fsS "%s"\n' "$ACCESS_INGRESS_HTTP_URL"
fi
if [ -n "$ACCESS_INGRESS_TCP_BIND" ]; then
  printf '  python3 -c '\''import socket; s = socket.create_connection(("%s", %s), timeout=3); s.sendall(b"hello from host\\n"); s.shutdown(socket.SHUT_WR); print(s.recv(4096).decode())'\''\n' "$ACCESS_INGRESS_TCP_HOST" "$ACCESS_INGRESS_TCP_PORT"
fi
if [ -n "$ACCESS_INGRESS_UDP_BIND" ]; then
  printf '  python3 -c '\''import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b"hello from host\\n", ("%s", %s)); print(s.recvfrom(4096)[0].decode())'\''\n' "$ACCESS_INGRESS_UDP_HOST" "$ACCESS_INGRESS_UDP_PORT"
fi
printf '\nResolved contract snapshot:\n'
printf '%s\n' "$RESOLVED_CONTRACT" | jq
