#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF >&2
usage: $0 <label> <command> [args...]

Optional environment:
  UHOST_DISPOSABLE_TARGET_LAYOUT=shared|unique
  UHOST_DISPOSABLE_TARGET_UNIQUE=1      # alias for unique layout
  UHOST_DISPOSABLE_TARGET_RUN_ID=<id>   # share one unique dir across helper calls
  UHOST_DISPOSABLE_TARGET_KEEP_RUNS=<n> # unique dirs kept per label (default: 3)
  UHOST_DISPOSABLE_TARGET_PRUNE=0|1     # prune older unique dirs (default: 1)
EOF
  exit 64
}

sanitize_component() {
  local value="$1"
  value="${value//[^A-Za-z0-9_.-]/-}"
  value="${value#-}"
  value="${value%-}"
  if [[ -z "$value" ]]; then
    value="default"
  fi
  printf '%s' "$value"
}

parse_bool() {
  local value="${1,,}"
  case "$value" in
    1|true|yes|on)
      return 0
      ;;
    0|false|no|off|'')
      return 1
      ;;
    *)
      return 2
      ;;
  esac
}

use_unique_layout() {
  local layout="${UHOST_DISPOSABLE_TARGET_LAYOUT:-}"
  local status

  if [[ -z "$layout" ]]; then
    if parse_bool "${UHOST_DISPOSABLE_TARGET_UNIQUE:-0}"; then
      return 0
    else
      status=$?
    fi
    if [[ "$status" -eq 1 ]]; then
      return 1
    fi
    echo "invalid UHOST_DISPOSABLE_TARGET_UNIQUE value: ${UHOST_DISPOSABLE_TARGET_UNIQUE:-}" >&2
    exit 64
  fi

  case "${layout,,}" in
    shared)
      return 1
      ;;
    unique)
      return 0
      ;;
    *)
      echo "invalid UHOST_DISPOSABLE_TARGET_LAYOUT value: ${layout}" >&2
      exit 64
      ;;
  esac
}

pruning_enabled() {
  local status
  if parse_bool "${UHOST_DISPOSABLE_TARGET_PRUNE:-1}"; then
    return 0
  else
    status=$?
  fi
  if [[ "$status" -eq 1 ]]; then
    return 1
  fi
  echo "invalid UHOST_DISPOSABLE_TARGET_PRUNE value: ${UHOST_DISPOSABLE_TARGET_PRUNE:-}" >&2
  exit 64
}

resolve_keep_runs() {
  local keep_runs="${UHOST_DISPOSABLE_TARGET_KEEP_RUNS:-3}"
  if [[ ! "$keep_runs" =~ ^[1-9][0-9]*$ ]]; then
    echo "UHOST_DISPOSABLE_TARGET_KEEP_RUNS must be a positive integer, got: ${keep_runs}" >&2
    exit 64
  fi
  printf '%s' "$keep_runs"
}

target_dir_is_active() {
  local dir="$1"
  local owner_file="${dir}/.uhost-disposable-target-owner.pid"
  local owner_pid

  if [[ ! -f "$owner_file" ]]; then
    return 1
  fi

  owner_pid="$(<"$owner_file")"
  if [[ ! "$owner_pid" =~ ^[0-9]+$ ]]; then
    rm -f -- "$owner_file"
    return 1
  fi

  if kill -0 "$owner_pid" 2>/dev/null; then
    return 0
  fi

  rm -f -- "$owner_file"
  return 1
}

prune_unique_target_dirs() {
  local repo_target_root="$1"
  local label="$2"
  local current_dir="$3"
  local keep_runs="$4"
  local candidate_dirs=()
  local sorted_dirs=()
  local dir
  local kept=0
  local removed=0

  if ! pruning_enabled; then
    return
  fi

  shopt -s nullglob
  candidate_dirs=("${repo_target_root}/${label}".run-*)
  shopt -u nullglob

  if [[ "${#candidate_dirs[@]}" -le "$keep_runs" ]]; then
    return
  fi

  mapfile -t sorted_dirs < <(ls -1dt -- "${candidate_dirs[@]}" 2>/dev/null || true)

  for dir in "${sorted_dirs[@]}"; do
    if [[ -n "$current_dir" && "$dir" == "$current_dir" ]]; then
      kept=$((kept + 1))
      continue
    fi

    if target_dir_is_active "$dir"; then
      kept=$((kept + 1))
      continue
    fi

    if [[ "$kept" -lt "$keep_runs" ]]; then
      kept=$((kept + 1))
      continue
    fi

    rm -rf -- "$dir"
    removed=$((removed + 1))
  done

  if [[ "$removed" -gt 0 ]]; then
    echo "[cargo-target] pruned ${removed} disposable target dir(s) for label ${label}"
  fi
}

allocate_unique_target_dir() {
  local repo_target_root="$1"
  local label="$2"
  local candidate_run_id

  if [[ -n "${UHOST_DISPOSABLE_TARGET_RUN_ID:-}" ]]; then
    candidate_run_id="$(sanitize_component "${UHOST_DISPOSABLE_TARGET_RUN_ID}")"
  else
    candidate_run_id="$(sanitize_component "$(date -u +%Y%m%dT%H%M%SZ)-$$-${RANDOM}${RANDOM}")"
  fi

  local candidate_dir="${repo_target_root}/${label}.run-${candidate_run_id}"
  while [[ -e "$candidate_dir" && -z "${UHOST_DISPOSABLE_TARGET_RUN_ID:-}" ]]; do
    candidate_run_id="$(sanitize_component "$(date -u +%Y%m%dT%H%M%SZ)-$$-${RANDOM}${RANDOM}")"
    candidate_dir="${repo_target_root}/${label}.run-${candidate_run_id}"
  done

  export UHOST_DISPOSABLE_TARGET_RUN_ID="${candidate_run_id}"
  export CARGO_TARGET_DIR="${candidate_dir}"
  mkdir -p "$CARGO_TARGET_DIR"
}

if [[ $# -lt 2 ]]; then
  usage
fi

label="$(sanitize_component "$1")"
shift

if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  repo_root="$(cd "$script_dir/.." && pwd)"
  repo_name="$(sanitize_component "$(basename "$repo_root")")"
  target_root="${UHOST_DISPOSABLE_TARGET_ROOT:-${TMPDIR:-/tmp}/uhost-cargo-targets}"
  repo_target_root="${target_root}/${repo_name}"

  mkdir -p "$repo_target_root"

  if use_unique_layout; then
    allocate_unique_target_dir "$repo_target_root" "$label"
    printf '%s\n' "$$" > "${CARGO_TARGET_DIR}/.uhost-disposable-target-owner.pid"
  else
    export CARGO_TARGET_DIR="${repo_target_root}/${label}"
    mkdir -p "$CARGO_TARGET_DIR"
  fi

  keep_runs="$(resolve_keep_runs)"
  prune_unique_target_dirs "$repo_target_root" "$label" "${CARGO_TARGET_DIR}" "$keep_runs"
  mkdir -p "$CARGO_TARGET_DIR"
  echo "[cargo-target] using disposable target dir: $CARGO_TARGET_DIR"
fi

exec "$@"
