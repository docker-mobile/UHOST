# uhost-svc-uvm-control

Purpose:

- Own UVM templates, instance records, snapshots, migrations, and reconciliation state.
- Provide the desired-state control surface for VM lifecycle operations.

Primary endpoints:

- `GET /uvm`
- `GET /uvm/control/summary`
- `GET/POST /uvm/templates`
- `GET/POST /uvm/instances`
- `GET /uvm/instances/{instance_id}/runtime-sessions`
- `GET /uvm/instances/{instance_id}/runtime-sessions/{session_id}`
- `GET /uvm/instances/{instance_id}/runtime-checkpoints`
- `GET /uvm/instances/{instance_id}/runtime-checkpoints/{checkpoint_id}`
- `GET /uvm/instances/{instance_id}/resolved-contract`
- `POST /uvm/instances/{instance_id}/start`
- `POST /uvm/instances/{instance_id}/stop`
- `POST /uvm/instances/{instance_id}/reboot`
- `POST /uvm/instances/{instance_id}/migrate`
- `POST /uvm/instances/{instance_id}/snapshot`
- `POST /uvm/instances/{instance_id}/restore`
- `GET /uvm/snapshots`
- `GET /uvm/migrations`
- `GET/POST /uvm/reconciliation`
- `GET /uvm/outbox`

State files:

- `uvm-control/templates.json`
- `uvm-control/instances.json`
- `uvm-control/snapshots.json`
- `uvm-control/migrations.json`
- `uvm-control/reconciliations.json`
- `uvm-control/audit.log`
- `uvm-control/outbox.json`

Operational notes:

- Reconciliation state persists control-plane intent versus observed node-plane runtime state.
- `GET /uvm/instances/{instance_id}/runtime-sessions*` and `.../runtime-checkpoints*` project sibling `uvm-node` truth for the requested control-plane instance while preserving the control service's list pagination and detail ETag/version behavior.
- `GET /uvm/instances/{instance_id}/resolved-contract` joins control, image, node, and observe truth into one derived view and reports mismatch or missing-evidence notes without failing the read path.
- Every mutating operation appends audit and outbox records.
