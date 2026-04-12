#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$REPO_ROOT/docs/generated"
JSON_PATH="$OUT_DIR/release-state.json"
MD_PATH="$OUT_DIR/release-state.md"

OPENAPI_PATH="openapi/control-plane-v1.yaml"
PROTO_PATH="proto/control-plane-v1.proto"
UVM_MANIFEST_PATH="docs/benchmarks/generated/uvm-stack-validation-manifest.json"
HOST_VALIDATION_PATH="docs/benchmarks/generated/host-validation.md"

declare -A OPERATOR_SURFACES=(
  ["Console status"]="services/uhost-svc-console/src/lib.rs|/console/status|Console dashboard snapshot derived from state-root counts|/console/status"
  ["Observe node-health"]="services/uhost-svc-observe/src/lib.rs|/observe/node-health|Node heartbeat + process-report summary from node stores|\\[\"observe\",[[:space:]]*\"node-health\"\\]"
  ["HA readiness"]="services/uhost-svc-ha/src/lib.rs|/ha/readiness-summary|Role/replication/failover assessment recorded in HA stores|\\[\"ha\",[[:space:]]*\"readiness-summary\"\\]"
  ["Scheduler summary"]="services/uhost-svc-scheduler/src/lib.rs|/scheduler/summary|Inventory and placement totals from scheduler state documents|\\[\"scheduler\",[[:space:]]*\"summary\"\\]"
  ["UVM observe summary"]="services/uhost-svc-uvm-observe/src/lib.rs|/uvm/observe/summary|Claim/evidence summary upheld in UVM observe stores|\\[\"uvm\",[[:space:]]*\"observe\",[[:space:]]*\"summary\"\\]"
  ["UVM control summary"]="services/uhost-svc-uvm-control/src/lib.rs|/uvm/control/summary|Template/instance state and claim/backend summary from control-plane records|\\[\"uvm\",[[:space:]]*\"control\",[[:space:]]*\"summary\"\\]"
  ["Control summary"]="services/uhost-svc-control/src/lib.rs|/control/summary|Workload placement overview from control service records|\\[\"control\",[[:space:]]*\"summary\"\\]"
  ["Billing summary"]="services/uhost-svc-billing/src/lib.rs|/billing/summary|Account/subscription/invoice/provider-sync totals from billing records|\\[\"billing\",[[:space:]]*\"summary\"\\]"
  ["Billing owner summaries"]="services/uhost-svc-billing/src/lib.rs|/billing/owner-summaries|Tenant-to-account linkage summary from billing records|\\[\"billing\",[[:space:]]*\"owner-summaries\"\\]"
  ["Secrets summary"]="services/uhost-svc-secrets/src/lib.rs|/secrets/summary|Secret/version/ownership totals from encrypted secret records|\\[\"secrets\",[[:space:]]*\"summary\"\\]"
  ["Identity summary"]="services/uhost-svc-identity/src/lib.rs|/identity/summary|Principal/session overview from identity stores|\\[\"identity\",[[:space:]]*\"summary\"\\]"
  ["Stream summary"]="services/uhost-svc-stream/src/lib.rs|/stream/summary|Managed stream, replay-log, and subscriber-lag summary from stream records|\\[\"stream\",[[:space:]]*\"summary\"\\]"
)

sha256_artifact() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
    return
  fi

  echo "missing sha256 checksum utility (expected sha256sum or shasum)" >&2
  exit 1
}

extract_json_string_field() {
  local path="$1"
  local field="$2"
  sed -n "s/^[[:space:]]*\"$field\":[[:space:]]*\"\\(.*\\)\"\\(,[[:space:]]*\\)\{0,1\}$/\\1/p" "$path" | head -n 1
}

extract_markdown_generated_at() {
  local path="$1"
  sed -n 's/^- Generated at: //p' "$path" | head -n 1
}

require_file() {
  local path="$1"
  if [ ! -f "$REPO_ROOT/$path" ]; then
    echo "missing required file: $path" >&2
    exit 1
  fi
}

require_file "$OPENAPI_PATH"
require_file "$PROTO_PATH"
require_file "$UVM_MANIFEST_PATH"
require_file "$HOST_VALIDATION_PATH"

surface_available() {
  local relative_path="$1"
  local endpoint="$2"
  local full_path="$REPO_ROOT/$relative_path"
  if [ ! -f "$full_path" ]; then
    echo "false"
    return
  fi
  if rg -q "$endpoint" "$full_path" >/dev/null 2>&1; then
    echo "true"
  else
    echo "false"
  fi
}

generate_surface_entries() {
  local first=true
  for name in "${!OPERATOR_SURFACES[@]}"; do
  IFS='|' read -r path endpoint note pattern <<< "${OPERATOR_SURFACES[$name]}"
  local available
  local matcher="${pattern:-$endpoint}"
  available=$(surface_available "$path" "$matcher")
    if [ "$first" = true ]; then
      first=false
    else
      echo ","
    fi
    cat <<JSON
    {
      "name": "$name",
      "path": "$path",
      "endpoint": "$endpoint",
      "notes": "$note",
      "available": $available
    }
JSON
  done
}

mkdir -p "$OUT_DIR"

generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
script_sha="$(sha256_artifact "$REPO_ROOT/scripts/generate-release-state.sh")"
openapi_sha="$(sha256_artifact "$REPO_ROOT/$OPENAPI_PATH")"
proto_sha="$(sha256_artifact "$REPO_ROOT/$PROTO_PATH")"
uvm_manifest_sha="$(sha256_artifact "$REPO_ROOT/$UVM_MANIFEST_PATH")"
host_validation_sha="$(sha256_artifact "$REPO_ROOT/$HOST_VALIDATION_PATH")"

openapi_lines="$(wc -l < "$REPO_ROOT/$OPENAPI_PATH" | tr -d '[:space:]')"
proto_lines="$(wc -l < "$REPO_ROOT/$PROTO_PATH" | tr -d '[:space:]')"

uvm_manifest_generated_at="$(extract_json_string_field "$REPO_ROOT/$UVM_MANIFEST_PATH" "generated_at")"
uvm_manifest_bundle="$(extract_json_string_field "$REPO_ROOT/$UVM_MANIFEST_PATH" "bundle")"
host_validation_generated_at="$(extract_markdown_generated_at "$REPO_ROOT/$HOST_VALIDATION_PATH")"

if [ -z "$uvm_manifest_generated_at" ]; then
  echo "failed to extract generated_at from $UVM_MANIFEST_PATH" >&2
  exit 1
fi
if [ -z "$host_validation_generated_at" ]; then
  echo "failed to extract generated timestamp from $HOST_VALIDATION_PATH" >&2
  exit 1
fi

host_measurement_mode="$(sed -n 's/^- Measurement mode: `\([^`]*\)`$/\1/p' "$REPO_ROOT/$HOST_VALIDATION_PATH" | head -n 1)"
host_execution_environment="$(sed -n 's/^- Execution environment: `\([^`]*\)`$/\1/p' "$REPO_ROOT/$HOST_VALIDATION_PATH" | head -n 1)"
host_uvm_claim_tier="$(sed -n 's/^- UVM claim tier: `\([^`]*\)`.*$/\1/p' "$REPO_ROOT/$HOST_VALIDATION_PATH" | head -n 1)"
host_qemu_claim_tier="$(sed -n 's/^- QEMU claim tier: `\([^`]*\)`.*$/\1/p' "$REPO_ROOT/$HOST_VALIDATION_PATH" | head -n 1)"

git_revision="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || true)"
if [ -z "$git_revision" ]; then
  git_revision="unknown"
fi

dirty=false
if [ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all 2>/dev/null || true)" ]; then
  dirty=true
fi

cat > "$JSON_PATH" <<EOF
{
  "schema_version": 1,
  "bundle": "release-state",
  "generated_at": "$generated_at",
  "generator": {
    "script": "scripts/generate-release-state.sh",
    "script_sha256": "$script_sha",
    "command": "bash scripts/generate-release-state.sh"
  },
  "git": {
    "revision": "$git_revision",
    "dirty": $dirty
  },
  "contracts": {
    "openapi": {
      "path": "$OPENAPI_PATH",
      "sha256": "$openapi_sha",
      "line_count": $openapi_lines
    },
    "proto": {
      "path": "$PROTO_PATH",
      "sha256": "$proto_sha",
      "line_count": $proto_lines
    }
  },
  "evidence": {
    "uvm_stack_manifest": {
      "path": "$UVM_MANIFEST_PATH",
      "bundle": "$uvm_manifest_bundle",
      "generated_at": "$uvm_manifest_generated_at",
      "sha256": "$uvm_manifest_sha"
    },
    "host_validation": {
      "path": "$HOST_VALIDATION_PATH",
      "generated_at": "$host_validation_generated_at",
      "measurement_mode": "$host_measurement_mode",
      "execution_environment": "$host_execution_environment",
      "uvm_claim_tier": "$host_uvm_claim_tier",
      "qemu_claim_tier": "$host_qemu_claim_tier",
      "sha256": "$host_validation_sha"
    }
  },
  "operator_surfaces": [
$(generate_surface_entries)
  ],
  "notes": [
    "This artifact is generated. Regenerate after contract or benchmark evidence updates.",
    "Human-facing status docs should link to docs/generated/release-state.md instead of restating mutable verification batches."
  ]
}
EOF

cat > "$MD_PATH" <<EOF
# Release State

- Generated at: \`$generated_at\`
- Generator command: \`bash scripts/generate-release-state.sh\`
- Git revision: \`$git_revision\`
- Git tree dirty: \`$dirty\`

## Contracts

| Contract | Path | SHA-256 | Lines |
| --- | --- | --- | ---: |
| OpenAPI | \`$OPENAPI_PATH\` | \`$openapi_sha\` | $openapi_lines |
| Protobuf | \`$PROTO_PATH\` | \`$proto_sha\` | $proto_lines |

## Evidence

| Artifact | Path | Generated at | SHA-256 |
| --- | --- | --- | --- |
| UVM stack manifest (\`$uvm_manifest_bundle\`) | \`$UVM_MANIFEST_PATH\` | \`$uvm_manifest_generated_at\` | \`$uvm_manifest_sha\` |
| Host validation report | \`$HOST_VALIDATION_PATH\` | \`$host_validation_generated_at\` | \`$host_validation_sha\` |

## Operator/Evidence Surfaces

| Surface | Path | Endpoint | Notes | Available |
| --- | --- | --- | --- | --- |
$(for name in "${!OPERATOR_SURFACES[@]}"; do
  IFS='|' read -r path endpoint note pattern <<< "${OPERATOR_SURFACES[$name]}"
  matcher="${pattern:-$endpoint}"
  available=$(surface_available "$path" "$matcher")
  echo "| $name | \`$path\` | \`$endpoint\` | $note | $available |"
done)

## Host Validation Summary

- Measurement mode: \`$host_measurement_mode\`
- Execution environment: \`$host_execution_environment\`
- UVM claim tier: \`$host_uvm_claim_tier\`
- QEMU claim tier: \`$host_qemu_claim_tier\`

## Source Of Truth Policy

- Keep mutable verification state in generated artifacts.
- Link human docs to this file instead of maintaining manual command-history blocks.
EOF

echo "[release-state] wrote $JSON_PATH"
echo "[release-state] wrote $MD_PATH"
