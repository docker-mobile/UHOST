# uhost-svc-uvm-observe

Purpose:

- Own UVM perf attestations, failure reports, host evidence, claim decisions, and benchmark records.
- Publish evidence-backed runtime and benchmark views for the UVM program.

Primary endpoints:

- `GET /uvm/observe`
- `GET /uvm/observe/summary`
- `GET/POST /uvm/perf-attestations`
- `GET/POST /uvm/failure-reports`
- `GET/POST /uvm/host-evidence`
- `GET /uvm/preflight-evidence-artifacts`
- `GET/POST /uvm/claim-decisions`
- `GET/POST /uvm/benchmark-campaigns`
- `GET /uvm/benchmark-campaigns/{campaign_id}/summary`
- `GET/POST /uvm/benchmark-baselines`
- `GET/POST /uvm/benchmark-results`
- `GET /uvm/native-claim-status`
- `GET /uvm/observe-outbox`

State files:

- `uvm-observe/perf_attestations.json`
- `uvm-observe/failure_reports.json`
- `uvm-observe/host_evidence.json`
- `uvm-observe/claim_decisions.json`
- `uvm-observe/benchmark_campaigns.json`
- `uvm-observe/benchmark_baselines.json`
- `uvm-observe/benchmark_results.json`
- `uvm-observe/audit.log`
- `uvm-observe/outbox.json`

Operational notes:

- The service reads `uvm-node/runtime_sessions.json`, `uvm-node/runtime_session_intents.json`, and `uvm-node/runtime_preflights.json` to derive claim and benchmark views.
- Runtime preflight evidence is republished as read-only observe artifacts keyed by canonical `host_class_evidence_key` so claim and benchmark views can join on shared host posture.
- Measured benchmark baselines and results are keyed by `host_class_evidence_key + workload_class + scenario + engine`; measured baselines now require both `scenario` and `host_evidence_id` so scope matching stays explicit, and measured comparisons reject mixed lineage unless `measurement_mode` plus guest-run lineage for guest targets also align.
- In the checked-in beta workflow, startup scans the nearest ancestor workspace for `docs/benchmarks/generated/uvm-stack-validation-manifest.json` and auto-ingests generated validation reports into deterministic benchmark campaigns plus keyed measured baseline/result rows.
- That startup scan is a source-checkout convenience for the current evidence bundle; packaged deployments should treat it as beta-era ingestion behavior, not as a globally distributed evidence feed.
- Evidence mutations remain auditable and outbox-backed.
- `/uvm/observe/summary` aggregates the current perf attestations, host evidence, claim decisions, and benchmark results for operator reference.
