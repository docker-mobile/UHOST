#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
denylist="${root_dir}/ci/vuln-denylist.txt"
audit_ignorelist="${root_dir}/ci/vuln-audit-ignore.txt"
lock_file="${root_dir}/Cargo.lock"

cd "${root_dir}"

if [[ ! -f "${denylist}" ]]; then
  echo "Vulnerability denylist not found: ${denylist}" >&2
  exit 1
fi

if [[ ! -f "${audit_ignorelist}" ]]; then
  echo "Vulnerability audit ignorelist not found: ${audit_ignorelist}" >&2
  exit 1
fi

if [[ ! -f "${lock_file}" ]]; then
  echo "Cargo.lock not found" >&2
  exit 1
fi

declare -A denied
while read -r crate version reason; do
  if [[ -z "${crate}" || "${crate}" == \#* ]]; then
    continue
  fi
  denied["${crate}@${version}"]="${reason:-denied}"
done < "${denylist}"

declare -a audit_ignore_args=()
while read -r advisory_id reason; do
  if [[ -z "${advisory_id}" || "${advisory_id}" == \#* ]]; then
    continue
  fi
  audit_ignore_args+=(--ignore "${advisory_id}")
done < "${audit_ignorelist}"

found_issue="false"
current_name=""
current_version=""
while IFS= read -r line; do
  if [[ "${line}" =~ ^name\ =\ \"([^\"]+)\"$ ]]; then
    current_name="${BASH_REMATCH[1]}"
  elif [[ "${line}" =~ ^version\ =\ \"([^\"]+)\"$ ]]; then
    current_version="${BASH_REMATCH[1]}"
    key="${current_name}@${current_version}"
    if [[ -n "${denied[${key}]:-}" ]]; then
      echo "Denied dependency detected: ${key} (${denied[${key}]})"
      found_issue="true"
    fi
  fi
done < "${lock_file}"

if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "cargo-audit must be installed for the vulnerability gate" >&2
  exit 1
fi

echo "Running cargo-audit..."
cargo audit --deny warnings "${audit_ignore_args[@]}"

if [[ "${found_issue}" == "true" ]]; then
  echo "Vulnerability denylist gate failed"
  exit 1
fi

echo "Vulnerability checks passed"
