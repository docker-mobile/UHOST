# uhost-svc-uvm-node

Purpose:

- Own node capabilities, device profiles, runtime sessions, checkpoints, migrations, and heartbeat state.
- Provide the runtime-adjacent orchestration surface for UVM execution and recovery.

Primary endpoints:

- `GET /uvm/node`
- `GET /uvm/node-operations`
- `GET/POST /uvm/node-capabilities`
- `POST /uvm/node-capabilities/select-adapter`
- `GET/POST /uvm/device-profiles`
- `GET/POST /uvm/node-drains`
- `GET /uvm/runtime`
- `GET/POST /uvm/runtime/instances`
- `POST /uvm/runtime/instances/{session_id}/prepare`
- `POST /uvm/runtime/instances/{session_id}/start`
- `POST /uvm/runtime/instances/{session_id}/stop`
- `POST /uvm/runtime/instances/{session_id}/restore`
- `POST /uvm/runtime/instances/{session_id}/mark-failed`
- `POST /uvm/runtime/instances/{session_id}/recover`
- `POST /uvm/runtime/instances/{session_id}/recover-complete`
- `POST /uvm/runtime/instances/{session_id}/heartbeat`
- `GET/POST /uvm/runtime/checkpoints`
- `GET/POST /uvm/runtime/preflight`
- `GET /uvm/runtime/heartbeats`
- `GET /uvm/runtime/health`
- `GET /uvm/runtime/migrations`
- `POST /uvm/runtime/migrations/preflight`
- `POST /uvm/runtime/migrations`
- `POST /uvm/runtime/migrations/{migration_id}/commit`
- `POST /uvm/runtime/migrations/{migration_id}/rollback`
- `POST /uvm/runtime/migrations/{migration_id}/fail`
- `GET /uvm/node-outbox`

State files:

- `uvm-node/node_capabilities.json`
- `uvm-node/device_profiles.json`
- `uvm-node/runtime_sessions.json`
- `uvm-node/runtime_session_intents.json`
- `uvm-node/runner_supervision.json`
- `uvm-node/runtime_preflights.json`
- `uvm-node/runtime_checkpoints.json`
- `uvm-node/runtime_migrations.json`
- `uvm-node/node_operations.json`
- `uvm-node/node_drains.json`
- `uvm-node/runtime_heartbeats.json`
- `uvm-node/audit.log`
- `uvm-node/outbox.json`

Operational notes:

- Runtime session intents, preflights, and migrations are persisted separately from live session state.
- Software-backed runtime sessions persist runner-supervision records per `runtime_session_id:runtime_incarnation` and use them to spawn/watch `uhost-uvm-runner` plus its lifecycle/heartbeat witness stream.
- Runtime heartbeats persist authoritative `runner_sequence_id` and `lifecycle_event_id` markers, and `GET /uvm/runtime/heartbeats` returns them in deterministic runner order for replay/query flows.
- Recovery and migration resolution remain auditable and outbox-backed.
- When sibling `uvm-image` state publishes verified software artifacts, software-backed runtime contracts consume those local `file://` disk and firmware artifact references.
