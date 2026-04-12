#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  exec bash "$root_dir/scripts/with-disposable-target-dir.sh" generate-sbom bash "$0" "$@"
fi
cd "${root_dir}"

target_dir="${CARGO_TARGET_DIR:-${root_dir}/target}"
out_dir="${target_dir}/sbom"
mkdir -p "${out_dir}"

cargo metadata --format-version=1 --locked > "${out_dir}/cargo-metadata.json"
cargo tree --workspace --locked > "${out_dir}/cargo-tree.txt"
cargo tree --workspace --locked --duplicates > "${out_dir}/cargo-duplicates.txt"

echo "SBOM artifacts written to ${out_dir}"
