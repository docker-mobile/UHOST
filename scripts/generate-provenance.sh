#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  exec bash "$root_dir/scripts/with-disposable-target-dir.sh" generate-provenance bash "$0" "$@"
fi
cd "${root_dir}"

target_dir="${CARGO_TARGET_DIR:-${root_dir}/target}"
out_dir="${target_dir}/provenance"
manifest_path="${target_dir}/signatures/artifact-manifest.json"
artifacts_dir="${target_dir}/release"
mkdir -p "${out_dir}"

if [[ ! -f "${manifest_path}" ]]; then
  echo "artifact manifest not found: ${manifest_path}" >&2
  exit 1
fi

if [[ ! -f "${root_dir}/Cargo.lock" ]]; then
  echo "Cargo.lock not found" >&2
  exit 1
fi

if [[ -n "$(git -C "${root_dir}" status --porcelain --untracked-files=all 2>/dev/null)" ]]; then
  echo "provenance generation requires a clean source tree" >&2
  exit 1
fi

git_commit="$(git -C "${root_dir}" rev-parse --verify HEAD 2>/dev/null || true)"
if [[ -z "${git_commit}" ]]; then
  echo "failed to resolve git commit for provenance attestation" >&2
  exit 1
fi

rustc_version="$(rustc --version)"
cargo_version="$(cargo --version)"
build_timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cargo_lock_sha256="$(sha256sum "${root_dir}/Cargo.lock" | awk '{print $1}')"
manifest_sha256="$(sha256sum "${manifest_path}" | awk '{print $1}')"

artifacts=(
  "uhostd"
  "uhostctl"
  "uhost-uvm-runner"
)

{
  cat <<EOF
{
  "builder": {
    "name": "project-uhost-ci",
    "version": 2
  },
  "source": {
    "repository": "Project-Uhost",
    "commit": "${git_commit}",
    "dirty": false
  },
  "build": {
    "timestamp_utc": "${build_timestamp}",
    "rustc": "${rustc_version}",
    "cargo": "${cargo_version}",
    "locked": true,
    "cargo_lock_sha256": "${cargo_lock_sha256}",
    "artifact_manifest_sha256": "${manifest_sha256}",
    "artifacts": [
EOF

  for index in "${!artifacts[@]}"; do
    artifact="${artifacts[$index]}"
    path="${artifacts_dir}/${artifact}"
    if [[ ! -f "${path}" ]]; then
      echo "missing release artifact: ${path}" >&2
      exit 1
    fi
    digest="$(sha256sum "${path}" | awk '{print $1}')"
    printf '      { "artifact": "%s", "path": "%s", "sha256": "%s" }' "${artifact}" "${path}" "${digest}"
    if (( index + 1 < ${#artifacts[@]} )); then
      printf ',\n'
    else
      printf '\n'
    fi
  done

  cat <<EOF
    ]
  }
}
EOF
} > "${out_dir}/attestation.json"

echo "Provenance attestation written to ${out_dir}/attestation.json"
