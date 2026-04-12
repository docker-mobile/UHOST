#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
config_path="${repo_root}/configs/prod/all-in-one.toml"

echo "Checking ${config_path#"${repo_root}/"} for checked-in production-secret hazards"

if grep -nE '^[[:space:]]*(master_key|bootstrap_admin_token)[[:space:]]*=' "${config_path}"; then
    echo "configs/prod/all-in-one.toml must not contain checked-in secret values" >&2
    exit 1
fi

if grep -nE '^[[:space:]]*mode[[:space:]]*=[[:space:]]*"distributed"' "${config_path}"; then
    echo "configs/prod/all-in-one.toml must not claim distributed mode" >&2
    exit 1
fi

if ! grep -qE '^[[:space:]]*mode[[:space:]]*=[[:space:]]*"all_in_one"' "${config_path}"; then
    echo "configs/prod/all-in-one.toml must declare all_in_one mode to match the current baseline" >&2
    exit 1
fi

if grep -niE '^[[:space:]]*[A-Za-z0-9_]+[[:space:]]*=[[:space:]]*".*(change-me|placeholder|example|sample|dummy|replace-me).*"' "${config_path}"; then
    echo "configs/prod/all-in-one.toml contains placeholder-like production values" >&2
    exit 1
fi

echo "Production config safety gate passed"
