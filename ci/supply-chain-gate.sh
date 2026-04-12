#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  exec bash "$root_dir/scripts/with-disposable-target-dir.sh" supply-chain-gate bash "$0" "$@"
fi
cd "${root_dir}"

target_dir="${CARGO_TARGET_DIR:-${root_dir}/target}"
artifact_manifest_path="${target_dir}/signatures/artifact-manifest.json"
provenance_path="${target_dir}/provenance/attestation.json"

if [[ -n "$(git -C "${root_dir}" status --porcelain --untracked-files=all 2>/dev/null)" ]]; then
  echo "Supply-chain gate requires a clean source tree" >&2
  exit 1
fi

bash scripts/generate-sbom.sh
bash ci/vuln-check.sh

cargo build --locked --release -p uhostd -p uhostctl -p uhost-uvm-runner
bash scripts/sign-artifacts.sh
bash scripts/generate-provenance.sh

for artifact in uhostd uhostctl uhost-uvm-runner; do
  artifact_path="${target_dir}/release/${artifact}"
  artifact_sha256="$(sha256sum "${artifact_path}" | awk '{print $1}')"
  cargo run --locked -q -p uhostctl -- release verify \
    --artifact "${artifact_path}" \
    --sha256 "${artifact_sha256}" \
    --manifest "${artifact_manifest_path}" \
    --provenance "${provenance_path}"
done

echo "Supply-chain gate passed"
