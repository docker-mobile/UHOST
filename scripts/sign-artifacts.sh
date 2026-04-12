#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  exec bash "$root_dir/scripts/with-disposable-target-dir.sh" sign-artifacts bash "$0" "$@"
fi
cd "${root_dir}"

target_dir="${CARGO_TARGET_DIR:-${root_dir}/target}"
artifacts_dir="${target_dir}/release"
sign_dir="${target_dir}/signatures"
mkdir -p "${sign_dir}"

artifacts=(
  "uhostd"
  "uhostctl"
  "uhost-uvm-runner"
)

manifest_path="${sign_dir}/artifact-manifest.json"
tmp_manifest="${sign_dir}/artifact-manifest.tmp"
echo "[" > "${tmp_manifest}"

first="true"
for artifact in "${artifacts[@]}"; do
  path="${artifacts_dir}/${artifact}"
  if [[ ! -f "${path}" ]]; then
    echo "missing release artifact: ${path}" >&2
    exit 1
  fi
  digest="$(sha256sum "${path}" | awk '{print $1}')"
  size_bytes="$(wc -c < "${path}" | tr -d '[:space:]')"
  if [[ "${first}" == "false" ]]; then
    echo "," >> "${tmp_manifest}"
  fi
  cat >> "${tmp_manifest}" <<EOF
  {
    "artifact": "${artifact}",
    "path": "${path}",
    "sha256": "${digest}",
    "size_bytes": ${size_bytes}
  }
EOF
  first="false"
done

echo "]" >> "${tmp_manifest}"
mv "${tmp_manifest}" "${manifest_path}"
echo "Artifact digest manifest written to ${manifest_path}"
