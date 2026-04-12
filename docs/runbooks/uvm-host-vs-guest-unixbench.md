# UVM Host-vs-Guest UnixBench Runbook

This runbook documents one narrow question: how the host UnixBench score
compares with the software-UVM guest UnixBench score produced by
`uhost-uvm-runner`.

## Purpose

- Generate bounded benchmark evidence.
- Compare host and guest score drift.
- Preserve honesty about whether the result is direct, partial, or modeled.

## Scope

This runbook is evidence-only. It does not by itself prove:

- isolation strength,
- commercial VPS certification,
- hardware-backed virtualization parity,
- production readiness.

## Command

```bash
bash scripts/run-uvm-host-vs-guest-unixbench.sh
```

Generated outputs:

- `docs/generated/uvm-host-vs-guest-unixbench.json`
- `docs/generated/uvm-host-vs-guest-unixbench.md`

## Environment Controls

- `UHOST_RUN_UVM_GUEST_CONTROL=1|0`
- `UHOST_UNIXBENCH_MAX_DRIFT_PCT=<number>`
- `UHOST_HOST_UNIXBENCH_COMMAND='<command>'`
- `UHOST_UVM_GUEST_ARTIFACT='<path>'`
- `UHOST_UVM_HOST_GUEST_OUT_DIR='<dir>'`
- `UHOST_UVM_NATIVE_GUEST_CONTROL_OUT_JSON='<path>'`
- `UHOST_UVM_NATIVE_GUEST_CONTROL_OUT_DIR='<dir>'`
- `UHOST_UVM_NATIVE_GUEST_CONTROL_WORK_DIR='<absolute dir>'`
- `UHOST_UVM_NATIVE_GUEST_CONTROL_DISK='<absolute path>'`
- `UHOST_UVM_SOFTVM_FIRMWARE_ARTIFACT='<absolute path>'`

## Interpretation

- `comparison.status=complete`
  Both host and guest scores were observed directly enough to compute drift.
- `comparison.status=partial`
  A scored host partial-result artifact was used because the full host suite did
  not finish cleanly.
- `comparison.status=inconclusive`
  Host or guest evidence is missing or invalid.
- `comparison.pass_minimal_drift=true`
  Drift is less than or equal to `max_drift_pct`.

## Honesty Rules

- No host score is fabricated.
- If the host suite fails but a scored partial-result artifact exists, the
  harness records partial host evidence instead of pretending the run was
  complete.
- If host UnixBench is unavailable and no scored result can be recovered, host
  status remains `unavailable`.
- Guest regeneration is off by default so the tracked evidence bundle is not
  overwritten on unsupported hosts.
- If explicit guest generation fails, the previous guest artifact is restored
  and the comparison remains `inconclusive`.
- Checked-in sample artifacts remain host-specific engineering evidence; if the
  guest summary reports `host_calibrated_full` or `host_calibrated_partial`,
  do not treat the resulting drift number as a general parity claim.

## Operational Notes

- `UHOST_UVM_GUEST_ARTIFACT` defaults to the tracked guest-control artifact.
- The regenerated guest path accepts a host-local firmware binary through
  `UHOST_UVM_SOFTVM_FIRMWARE_ARTIFACT` while preserving the advertised firmware
  profile in the output contract.
- Guest disk and optional install ISO must resolve to host-local absolute paths
  or `file://` URIs during regeneration.
- When a scored local host UnixBench artifact is present, the software guest
  summary records benchmark provenance as `host_calibrated_full` or
  `host_calibrated_partial`; otherwise it falls back to `synthetic_baseline`.

## Related Docs

- [Host Readiness](host-readiness.md)
- [UVM Virtualization Stack Architecture](../uvm-virtualization-stack.md)
- [Threat Model](../threat-model.md)
