#!/usr/bin/env bash
set -u

OUT_DIR="${UHOST_UVM_HOST_GUEST_OUT_DIR:-docs/generated}"
GUEST_ARTIFACT="${UHOST_UVM_GUEST_ARTIFACT:-docs/benchmarks/generated/uvm-native-guest-control.json}"
HOST_SUMMARY_LOG="$OUT_DIR/host-unixbench-summary.log"
HOST_FULL_LOG="$OUT_DIR/host-unixbench-full.log"
OUT_JSON="$OUT_DIR/uvm-host-vs-guest-unixbench.json"
OUT_MD="$OUT_DIR/uvm-host-vs-guest-unixbench.md"
GUEST_RUN_LOG="$OUT_DIR/uvm-native-guest-control.run.log"
UNIXBENCH_RESULTS_DIR="${UHOST_UNIXBENCH_RESULTS_DIR:-/opt/byte-unixbench/UnixBench/results}"

RUN_GUEST="${UHOST_RUN_UVM_GUEST_CONTROL:-0}"
MAX_DRIFT_PCT="${UHOST_UNIXBENCH_MAX_DRIFT_PCT:-5}"
HOST_COMMAND="${UHOST_HOST_UNIXBENCH_COMMAND:-}"

mkdir -p "$OUT_DIR"

extract_index_score() {
  local path="$1"
  if [ ! -f "$path" ]; then
    return 1
  fi
  grep -m1 "System Benchmarks Index Score" "$path" \
    | grep -Eo '[0-9]+(\.[0-9]+)?' \
    | tail -n1
}

latest_unixbench_result_with_score() {
  local latest=""
  if [ ! -d "$UNIXBENCH_RESULTS_DIR" ]; then
    return 1
  fi
  latest="$(
    find "$UNIXBENCH_RESULTS_DIR" -maxdepth 1 -type f 2>/dev/null \
      | grep -Ev '\.(html|log)$' \
      | while read -r path; do
          if grep -q "System Benchmarks Index Score" "$path" 2>/dev/null; then
            printf '%s\n' "$path"
          fi
        done \
      | xargs -r ls -1t \
      | head -n1
  )"
  if [ -z "$latest" ]; then
    return 1
  fi
  printf "%s" "$latest"
}

unixbench_result_is_partial() {
  local path="$1"
  if [ ! -f "$path" ]; then
    return 1
  fi
  grep -q "System Benchmarks Index Score (Partial Only)" "$path"
}

fmt_num_or_na() {
  local value="$1"
  if [ -n "$value" ]; then
    printf "%s" "$value"
  else
    printf "n/a"
  fi
}

generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

guest_status="ready"
guest_reason=""
guest_score=""
guest_artifact_backup=""
guest_artifact_had_backup="false"

if [ "$RUN_GUEST" = "1" ]; then
  if [ -f "$GUEST_ARTIFACT" ]; then
    guest_artifact_backup="$(mktemp)"
    cp "$GUEST_ARTIFACT" "$guest_artifact_backup"
    guest_artifact_had_backup="true"
  fi
  if ! UHOST_UVM_NATIVE_GUEST_CONTROL_OUT_JSON="$GUEST_ARTIFACT" \
    bash scripts/run-uvm-native-guest-control.sh >"$GUEST_RUN_LOG" 2>&1; then
    if [ "$guest_artifact_had_backup" = "true" ]; then
      cp "$guest_artifact_backup" "$GUEST_ARTIFACT"
    else
      rm -f "$GUEST_ARTIFACT"
    fi
    guest_status="blocked"
    guest_reason="failed to generate guest artifact via scripts/run-uvm-native-guest-control.sh"
  fi
fi

if [ "$guest_status" = "ready" ]; then
  if [ ! -f "$GUEST_ARTIFACT" ]; then
    guest_status="blocked"
    guest_reason="guest artifact missing at configured UHOST_UVM_GUEST_ARTIFACT path"
  else
    guest_score="$(extract_index_score "$GUEST_ARTIFACT" || true)"
    if [ -z "$guest_score" ]; then
      guest_status="blocked"
      guest_reason="guest artifact does not contain a UnixBench index score"
    fi
  fi
fi

host_status="ready"
host_reason=""
host_score=""
host_command_failed=false
host_result_path=""
host_measurement_kind="full"

if [ -n "$HOST_COMMAND" ]; then
  if ! bash -lc "$HOST_COMMAND" >"$HOST_FULL_LOG" 2>&1; then
    host_command_failed=true
    host_reason="host benchmark command failed"
  fi
else
  if command -v unixbench >/dev/null 2>&1; then
    if ! unixbench --summary >"$HOST_SUMMARY_LOG" 2>&1; then
      host_command_failed=true
      host_reason="unixbench --summary failed on host"
    fi
    host_result_path="$(latest_unixbench_result_with_score || true)"
    if [ -n "$host_result_path" ] && [ -f "$host_result_path" ]; then
      cp "$host_result_path" "$HOST_FULL_LOG"
    fi
  else
    host_status="unavailable"
    host_reason="unixbench binary not found on host; install UnixBench or set UHOST_HOST_UNIXBENCH_COMMAND"
  fi
fi

if [ "$host_status" = "ready" ]; then
  if [ -n "$HOST_COMMAND" ]; then
    host_score="$(extract_index_score "$HOST_FULL_LOG" || true)"
    if [ -f "$HOST_FULL_LOG" ] && unixbench_result_is_partial "$HOST_FULL_LOG"; then
      host_measurement_kind="partial"
    fi
  else
    host_score="$(extract_index_score "$HOST_SUMMARY_LOG" || true)"
    if [ -z "$host_score" ] && [ -f "$HOST_FULL_LOG" ]; then
      host_score="$(extract_index_score "$HOST_FULL_LOG" || true)"
      if [ -n "$host_score" ] && unixbench_result_is_partial "$HOST_FULL_LOG"; then
        host_measurement_kind="partial"
      fi
    fi
  fi
  if [ -z "$host_score" ]; then
    host_result_path="${host_result_path:-$(latest_unixbench_result_with_score || true)}"
    if [ -n "$host_result_path" ] && [ -f "$host_result_path" ]; then
      cp "$host_result_path" "$HOST_FULL_LOG"
      host_score="$(extract_index_score "$HOST_FULL_LOG" || true)"
      if [ -n "$host_score" ] && unixbench_result_is_partial "$HOST_FULL_LOG"; then
        host_measurement_kind="partial"
      fi
    fi
  fi
  if [ -z "$host_score" ]; then
    host_status="unavailable"
    host_reason="host benchmark output does not contain a UnixBench index score"
  elif [ "$host_measurement_kind" = "partial" ]; then
    if [ "$host_command_failed" = "true" ]; then
      host_reason="host benchmark score recovered from partial UnixBench result artifact"
    else
      host_reason="host benchmark score reflects a partial UnixBench result"
    fi
  elif [ "$host_command_failed" = "true" ]; then
    host_reason="host benchmark score recovered from latest UnixBench result artifact"
  fi
fi

comparison_status="inconclusive"
comparison_reason="host and guest evidence are not both available"
absolute_diff=""
drift_pct=""
pass_minimal_drift=false

if [ "$host_status" = "ready" ] && [ "$guest_status" = "ready" ]; then
  absolute_diff="$(awk -v h="$host_score" -v g="$guest_score" 'BEGIN { d=h-g; if (d<0) d=-d; printf "%.3f", d }')"
  drift_pct="$(awk -v h="$host_score" -v g="$guest_score" 'BEGIN { d=h-g; if (d<0) d=-d; if (h<=0) { print "" } else { printf "%.3f", (d/h)*100.0 } }')"
  if [ -n "$drift_pct" ]; then
    pass_minimal_drift="$(
      awk -v p="$drift_pct" -v max="$MAX_DRIFT_PCT" 'BEGIN { if (p <= max) print "true"; else print "false" }'
    )"
    if [ "$host_measurement_kind" = "partial" ]; then
      comparison_status="partial"
      if [ "$pass_minimal_drift" = "true" ]; then
        comparison_reason="host-vs-guest score drift is within threshold using partial host UnixBench evidence"
      else
        comparison_reason="host-vs-guest score drift exceeds threshold using partial host UnixBench evidence"
      fi
    else
      comparison_status="complete"
      if [ "$pass_minimal_drift" = "true" ]; then
        comparison_reason="host-vs-guest score drift is within threshold"
      else
        comparison_reason="host-vs-guest score drift exceeds threshold"
      fi
    fi
  else
    comparison_status="inconclusive"
    comparison_reason="failed to compute drift percentage due to invalid host score"
  fi
fi

cat >"$OUT_JSON" <<EOF
{
  "generated_at": "$generated_at",
  "schema_version": 2,
  "evidence_kind": "uvm_host_vs_guest_unixbench",
  "inputs": {
    "guest_artifact": "$GUEST_ARTIFACT",
    "host_summary_log": "$HOST_SUMMARY_LOG",
    "host_full_log": "$HOST_FULL_LOG",
    "unixbench_results_dir": "$UNIXBENCH_RESULTS_DIR",
    "max_drift_pct": $MAX_DRIFT_PCT
  },
  "host": {
    "status": "$host_status",
    "reason": "$host_reason",
    "measurement_kind": "$host_measurement_kind",
    "score_source": "$host_result_path",
    "index_score": ${host_score:-null}
  },
  "guest": {
    "status": "$guest_status",
    "reason": "$guest_reason",
    "index_score": ${guest_score:-null}
  },
  "comparison": {
    "status": "$comparison_status",
    "reason": "$comparison_reason",
    "absolute_diff": ${absolute_diff:-null},
    "drift_pct": ${drift_pct:-null},
    "pass_minimal_drift": $pass_minimal_drift
  }
}
EOF

cat >"$OUT_MD" <<EOF
# UVM Host-vs-Guest UnixBench Evidence

- Generated at: \`$generated_at\`
- Max allowed drift (%): \`$MAX_DRIFT_PCT\`
- Host status: \`$host_status\`
- Guest status: \`$guest_status\`
- Comparison status: \`$comparison_status\`
- Comparison reason: $comparison_reason
- Host measurement kind: \`$host_measurement_kind\`

## Scores

- Host UnixBench index score: $(fmt_num_or_na "$host_score")
- Guest UnixBench index score: $(fmt_num_or_na "$guest_score")
- Absolute difference: $(fmt_num_or_na "$absolute_diff")
- Drift percent: $(fmt_num_or_na "$drift_pct")
- Pass minimal drift threshold: \`$pass_minimal_drift\`

## Evidence paths

- Guest artifact: \`$GUEST_ARTIFACT\`
- Host summary log: \`$HOST_SUMMARY_LOG\`
- Host full log: \`$HOST_FULL_LOG\`
- Host score source: \`$host_result_path\`
- Guest run log: \`$GUEST_RUN_LOG\`

## Notes

- This harness does not fabricate host benchmark numbers.
- If the host suite does not finish cleanly but a UnixBench result file with a score exists, the harness records that score as \`partial\` evidence instead of fabricating a full run.
- If host UnixBench is unavailable and no scored result file can be recovered, the result remains \`inconclusive\`.
- Fresh guest artifact generation is disabled by default so the script does not clobber the tracked wave3 evidence bundle on unsupported hosts.
- Use \`UHOST_HOST_UNIXBENCH_COMMAND\` to provide a custom host benchmark command.
EOF

if [ -n "$guest_artifact_backup" ]; then
  rm -f "$guest_artifact_backup"
fi

echo "==> host-vs-guest UnixBench artifact written to $OUT_JSON"
echo "==> host-vs-guest UnixBench report written to $OUT_MD"
