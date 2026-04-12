#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: bash scripts/host-capability-preflight.sh [--profile <name>]... [--deep]

Profiles:
  all-in-one-dev  Minimal local Rust/runtime exploration
  rust-ci         Native Rust fmt/clippy/test validation
  wave-evidence   Wave1/Wave3 evidence-gate readiness
  perf-gate       Rust validation plus benchmark-capable toolchain
  supply-chain    SBOM/provenance/signature release-gate readiness
  qemu-evidence   QEMU/BIOS/cloud-image evidence generation
  kvm-native      Native KVM-backed UVM validation on Linux

Examples:
  bash scripts/host-capability-preflight.sh
  bash scripts/host-capability-preflight.sh --profile rust-ci
  bash scripts/host-capability-preflight.sh --profile wave-evidence --deep
  bash scripts/host-capability-preflight.sh --profile supply-chain
  bash scripts/host-capability-preflight.sh --profile qemu-evidence --profile kvm-native
EOF
}

list_profiles() {
  cat <<'EOF'
all-in-one-dev
rust-ci
wave-evidence
perf-gate
supply-chain
qemu-evidence
kvm-native
EOF
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

has_cpu_virtualization_flag() {
  grep -Eq '(^flags|^Features)[[:space:]]*:.* (vmx|svm)( |$)' /proc/cpuinfo 2>/dev/null
}

is_container_restricted() {
  if [[ -f "/run/.containerenv" || -f "/.dockerenv" ]]; then
    return 0
  fi
  if grep -Eiq '(docker|kubepods|containerd|podman|lxc)' /proc/1/cgroup 2>/dev/null; then
    return 0
  fi
  return 1
}

yes_no() {
  if [[ "$1" == "1" ]]; then
    printf 'yes'
  else
    printf 'no'
  fi
}

parse_pinned_rust_toolchain() {
  local value
  value="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' rust-toolchain.toml | head -n 1)"
  if [[ -n "${value}" ]]; then
    printf '%s' "${value}"
    return 0
  fi
  return 1
}

extract_rustc_version() {
  local version
  version="$(rustc --version 2>/dev/null | awk '{print $2}')"
  if [[ -n "${version}" ]]; then
    printf '%s' "${version}"
    return 0
  fi
  return 1
}

dir_writable_or_creatable() {
  local path="$1"
  if [[ -d "${path}" ]]; then
    [[ -w "${path}" ]]
    return
  fi
  local parent
  parent="$(dirname "${path}")"
  [[ -d "${parent}" && -w "${parent}" ]]
}

add_blocker() {
  local item="$1"
  profile_blockers+=("${item}")
}

add_limit() {
  local item="$1"
  profile_limits+=("${item}")
}

add_note() {
  local item="$1"
  profile_notes+=("${item}")
}

require_cmd_or_blocker() {
  local cmd="$1"
  has_cmd "${cmd}" || add_blocker "missing command: ${cmd}"
}

require_path_or_blocker() {
  local path="$1"
  [[ -e "${path}" ]] || add_blocker "missing path: ${path}"
}

require_exec_or_blocker() {
  local path="$1"
  [[ -x "${path}" ]] || add_blocker "missing executable: ${path}"
}

require_file_or_blocker() {
  local path="$1"
  [[ -f "${path}" ]] || add_blocker "missing file: ${path}"
}

require_dir_writable_or_blocker() {
  local path="$1"
  dir_writable_or_creatable "${path}" || add_blocker "directory not writable/creatable: ${path}"
}

check_rust_ci_prerequisites() {
  require_cmd_or_blocker "rustc"
  require_cmd_or_blocker "cargo"
  require_cmd_or_blocker "cc"
  require_cmd_or_blocker "ld"
  require_cmd_or_blocker "make"
  require_cmd_or_blocker "pkg-config"
  require_cmd_or_blocker "grep"
  require_cmd_or_blocker "sed"
  require_cmd_or_blocker "head"
  require_cmd_or_blocker "awk"

  if ! parse_pinned_rust_toolchain >/dev/null; then
    add_blocker "failed to parse pinned channel from rust-toolchain.toml"
    return
  fi
  if has_cmd rustc; then
    pinned_toolchain="$(parse_pinned_rust_toolchain)"
    local rustc_version
    rustc_version="$(extract_rustc_version || true)"
    if [[ -z "${rustc_version}" ]]; then
      add_blocker "failed to resolve rustc version"
    elif [[ "${rustc_version}" != "${pinned_toolchain}" ]]; then
      add_blocker "rustc version mismatch: have ${rustc_version}, pinned ${pinned_toolchain}"
    fi
  fi

  if has_cmd cargo; then
    cargo fmt --version >/dev/null 2>&1 || add_blocker "cargo fmt component unavailable"
    cargo clippy -V >/dev/null 2>&1 || add_blocker "cargo clippy component unavailable"
    cargo metadata --format-version=1 --locked >/dev/null 2>&1 \
      || add_blocker "cargo metadata --locked failed"
  fi
}

profiles=()
deep_checks=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --profile" >&2
        usage >&2
        exit 1
      fi
      profiles+=("$2")
      shift 2
      ;;
    --deep)
      deep_checks=1
      shift
      ;;
    --list-profiles)
      list_profiles
      exit 0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

container_restricted=0
if is_container_restricted; then
  container_restricted=1
fi

cpu_virtualization=0
if has_cpu_virtualization_flag; then
  cpu_virtualization=1
fi

dev_kvm=0
if [[ -e /dev/kvm ]]; then
  dev_kvm=1
fi

dev_kvm_rw=0
if [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
  dev_kvm_rw=1
fi

rustc_cmd=0
cargo_cmd=0
cc_cmd=0
ld_cmd=0
make_cmd=0
pkg_config_cmd=0
qemu_x86_cmd=0
qemu_img_cmd=0
xorriso_cmd=0
docker_cmd=0
seabios_bios=0
timeout_cmd=0
script_cmd=0
ssh_cmd=0
ssh_keygen_cmd=0
pkill_cmd=0
sha256sum_cmd=0
git_cmd=0
cargo_audit_cmd=0

has_cmd rustc && rustc_cmd=1
has_cmd cargo && cargo_cmd=1
has_cmd cc && cc_cmd=1
has_cmd ld && ld_cmd=1
has_cmd make && make_cmd=1
has_cmd pkg-config && pkg_config_cmd=1
has_cmd qemu-system-x86_64 && qemu_x86_cmd=1
has_cmd qemu-img && qemu_img_cmd=1
has_cmd xorriso && xorriso_cmd=1
has_cmd docker && docker_cmd=1
has_cmd timeout && timeout_cmd=1
has_cmd script && script_cmd=1
has_cmd ssh && ssh_cmd=1
has_cmd ssh-keygen && ssh_keygen_cmd=1
has_cmd pkill && pkill_cmd=1
has_cmd sha256sum && sha256sum_cmd=1
has_cmd git && git_cmd=1
has_cmd cargo-audit && cargo_audit_cmd=1
[[ -f /usr/share/seabios/bios.bin ]] && seabios_bios=1

perl_json_pp=0
if has_cmd perl && perl -MJSON::PP -e 1 >/dev/null 2>&1; then
  perl_json_pp=1
fi

os_name="$(uname -s)"
arch_name="$(uname -m)"
pinned_toolchain="unknown"
if parse_pinned_rust_toolchain >/dev/null; then
  pinned_toolchain="$(parse_pinned_rust_toolchain)"
fi
installed_rustc="unknown"
if has_cmd rustc; then
  installed_rustc="$(extract_rustc_version || true)"
fi

measurement_mode="modeled"
if [[ "${os_name}" == "Linux" && "${dev_kvm_rw}" == "1" && "${container_restricted}" == "0" ]]; then
  measurement_mode="direct"
elif [[ "${cpu_virtualization}" == "1" || "${qemu_x86_cmd}" == "1" ]]; then
  measurement_mode="hybrid"
fi

echo "[summary] os=${os_name} arch=${arch_name} execution_environment=$([[ "${container_restricted}" == "1" ]] && printf 'container_restricted' || printf 'host') measurement_mode=${measurement_mode} requested_profiles=$(IFS=,; echo "${profiles[*]}") deep_checks=$(yes_no "${deep_checks}")"
echo "[host] cpu_virtualization_flag=$(yes_no "${cpu_virtualization}") /dev/kvm=$(yes_no "${dev_kvm}") /dev/kvm_rw=$(yes_no "${dev_kvm_rw}")"
echo "[host] rustc_installed=$(yes_no "${rustc_cmd}") rustc_version=${installed_rustc:-unknown} rust_toolchain_pinned=${pinned_toolchain}"
echo "[host] tool: cargo=$(yes_no "${cargo_cmd}") cc=$(yes_no "${cc_cmd}") ld=$(yes_no "${ld_cmd}") make=$(yes_no "${make_cmd}") pkg-config=$(yes_no "${pkg_config_cmd}") cargo-audit=$(yes_no "${cargo_audit_cmd}") sha256sum=$(yes_no "${sha256sum_cmd}")"
echo "[host] tool:qemu-system-x86_64=$(yes_no "${qemu_x86_cmd}") qemu-img=$(yes_no "${qemu_img_cmd}") xorriso=$(yes_no "${xorriso_cmd}") timeout=$(yes_no "${timeout_cmd}") script=$(yes_no "${script_cmd}") perl+JSON::PP=$(yes_no "${perl_json_pp}") seabios=$(yes_no "${seabios_bios}")"

if [[ "${#profiles[@]}" -eq 0 ]]; then
  echo "[host] no profiles requested; summary only"
  exit 0
fi

any_blocked=0

check_profile() {
  local profile="$1"
  profile_blockers=()
  profile_limits=()
  profile_notes=()
  local status="ready"
  local iso_url="https://cdimage.ubuntu.com/ubuntu-server/daily-live/current/resolute-live-server-amd64.iso"
  local iso_path="tmp/boot-probes/resolute-live-server-amd64.iso"
  local base_img_url="https://cloud-images.ubuntu.com/daily/server/resolute/current/resolute-server-cloudimg-amd64.img"
  local base_img_path="tmp/cloudimg/resolute-server-cloudimg-amd64.img"

  case "${profile}" in
    all-in-one-dev)
      require_cmd_or_blocker "rustc"
      require_cmd_or_blocker "cargo"
      require_file_or_blocker "configs/dev/all-in-one.toml"
      ;;
    rust-ci)
      check_rust_ci_prerequisites
      ;;
    wave-evidence)
      check_rust_ci_prerequisites
      require_file_or_blocker "ci/wave1-evidence-gate.sh"
      require_file_or_blocker "ci/wave3-evidence-gate.sh"
      require_file_or_blocker "ci/check-generated-benchmark-artifacts.sh"
      require_dir_writable_or_blocker "docs/benchmarks/generated"
      if [[ "${deep_checks}" == "1" ]]; then
        if ! bash ci/check-generated-benchmark-artifacts.sh >/dev/null 2>&1; then
          add_blocker "deep wave-evidence artifact freshness check failed"
        fi
      else
        add_note "run with --deep to execute benchmark artifact freshness checks"
      fi
      ;;
    perf-gate)
      check_rust_ci_prerequisites
      require_file_or_blocker "ci/perf-gate.sh"
      require_file_or_blocker "scripts/run-hyperscale.sh"
      if [[ "${deep_checks}" == "1" ]]; then
        bash ci/check-generated-benchmark-artifacts.sh >/dev/null 2>&1 \
          || add_limit "benchmark artifacts are missing or stale for perf-gate"
      else
        add_note "perf-gate also depends on generated benchmark evidence; run with --deep for artifact checks"
      fi
      ;;
    supply-chain)
      check_rust_ci_prerequisites
      require_file_or_blocker "ci/supply-chain-gate.sh"
      require_file_or_blocker "scripts/generate-sbom.sh"
      require_file_or_blocker "scripts/generate-provenance.sh"
      require_file_or_blocker "scripts/sign-artifacts.sh"
      require_cmd_or_blocker "git"
      require_cmd_or_blocker "cargo-audit"
      require_cmd_or_blocker "sha256sum"
      if has_cmd git; then
        git rev-parse --verify HEAD >/dev/null 2>&1 || add_blocker "git repository HEAD is unavailable"
        if [[ -n "$(git status --porcelain --untracked-files=all 2>/dev/null)" ]]; then
          add_blocker "source tree is not clean"
        fi
      fi
      if has_cmd cargo; then
        cargo tree --workspace --locked >/dev/null 2>&1 || add_blocker "cargo tree --workspace --locked failed"
      fi
      local target_dir="${CARGO_TARGET_DIR:-target}"
      require_dir_writable_or_blocker "${target_dir}/sbom"
      require_dir_writable_or_blocker "${target_dir}/provenance"
      require_dir_writable_or_blocker "${target_dir}/signatures"
      ;;
    qemu-evidence)
      check_rust_ci_prerequisites
      require_exec_or_blocker "/usr/bin/qemu-system-x86_64"
      require_cmd_or_blocker "qemu-img"
      require_cmd_or_blocker "xorriso"
      require_cmd_or_blocker "curl"
      require_cmd_or_blocker "timeout"
      require_cmd_or_blocker "script"
      [[ "${perl_json_pp}" == "1" ]] || add_blocker "missing perl JSON::PP support"
      require_file_or_blocker "/usr/share/seabios/bios.bin"
      require_dir_writable_or_blocker "docs/benchmarks/generated"
      require_dir_writable_or_blocker "tmp/boot-probes"
      if [[ -s "${iso_path}" ]]; then
        :
      else
        if has_cmd curl; then
          if ! curl -fsIL --max-time 10 "${iso_url}" >/dev/null 2>&1; then
            add_limit "installer ISO cache missing and upstream is not reachable right now"
          fi
        else
          add_limit "installer ISO cache missing and curl is unavailable for fetch checks"
        fi
      fi
      if [[ "${deep_checks}" == "1" ]]; then
        if [[ ! -s "${base_img_path}" ]]; then
          if has_cmd curl; then
            curl -fsIL --max-time 10 "${base_img_url}" >/dev/null 2>&1 \
              || add_limit "cloud image cache missing and upstream is not reachable right now"
          fi
        fi
      else
        add_note "run with --deep to check cloud image fetchability used by guest-control scripts"
      fi
      ;;
    kvm-native)
      check_rust_ci_prerequisites
      require_exec_or_blocker "/usr/bin/qemu-system-x86_64"
      if [[ "${os_name}" != "Linux" ]]; then
        add_blocker "kvm-native requires Linux host"
      fi
      if [[ "${cpu_virtualization}" != "1" ]]; then
        add_blocker "cpu virtualization flag (vmx/svm) is unavailable"
      fi
      if [[ "${dev_kvm_rw}" != "1" ]]; then
        add_blocker "/dev/kvm is missing or lacks read/write access"
      fi
      if [[ "${container_restricted}" == "1" ]]; then
        add_blocker "container-restricted environment blocks honest native KVM validation"
      fi
      if [[ "${measurement_mode}" != "direct" ]]; then
        add_note "measurement mode is ${measurement_mode}; native claims require direct mode"
      fi
      ;;
    *)
      echo "[profile:${profile}] unknown profile" >&2
      any_blocked=1
      return
      ;;
  esac

  if [[ "${#profile_blockers[@]}" -gt 0 ]]; then
    status="blocked"
  elif [[ "${#profile_limits[@]}" -gt 0 ]]; then
    status="limited"
  fi

  echo "[profile:${profile}] ${status}"

  if [[ "${#profile_blockers[@]}" -gt 0 ]]; then
    echo "  blockers: ${profile_blockers[*]}"
    any_blocked=1
  fi

  if [[ "${#profile_limits[@]}" -gt 0 ]]; then
    echo "  limits: ${profile_limits[*]}"
  fi

  if [[ "${#profile_notes[@]}" -gt 0 ]]; then
    for note in "${profile_notes[@]}"; do
      echo "  note: ${note}"
    done
  fi
}

for profile in "${profiles[@]}"; do
  check_profile "${profile}"
done

exit "${any_blocked}"
