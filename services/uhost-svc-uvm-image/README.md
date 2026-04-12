# uhost-svc-uvm-image

Purpose:

- Own image catalog state plus firmware-bundle, guest-profile, and overlay-policy documents.
- Provide compatibility and promotion controls for the UVM image pipeline.

Primary endpoints:

- `GET /uvm/image`
- `GET/POST /uvm/images`
- `GET /uvm/images/{image_id}/artifact-path`
- `POST /uvm/images/{image_id}/verify`
- `POST /uvm/images/{image_id}/promote`
- `GET /uvm/images/summary`
- `GET/POST /uvm/firmware-bundles`
- `GET /uvm/firmware-bundles/{firmware_id}/artifact-path`
- `GET/POST /uvm/guest-profiles`
- `GET/POST /uvm/overlay-policies`
- `GET/POST /uvm/region-cell-policies`
- `GET /uvm/compatibility-matrix`
- `GET /uvm/image-outbox`

State files:

- `uvm-image/images.json`
- `uvm-image/compatibility.json`
- `uvm-image/compatibility_revisions.json`
- `uvm-image/firmware_bundles.json`
- `uvm-image/guest_profiles.json`
- `uvm-image/overlay_policies.json`
- `uvm-image/region_cell_policies.json`
- `uvm-image/audit.log`
- `uvm-image/outbox.json`

Operational notes:

- Compatibility responses are derived from the persisted image, firmware, guest-profile, overlay-policy, and region/cell policy documents.
- Verified artifact-path endpoints return absolute local paths only for verified `file://` image and firmware records; remote artifacts or unverified records are rejected.
- Imported image records regenerate scoped compatibility evidence rows for every matching `(host_class, region, cell)` matrix row so operators can inspect publishable targets directly on the image artifact.
- Compatibility rows are keyed by the exact publication tuple `(host_class, region, cell, host_family, guest_architecture, accelerator_backend, machine_family, guest_profile, claim_tier)` and append revisions to `compatibility_revisions.json`.
- Promotion writes authoritative publication manifests keyed by `(image, channel, host_class, machine_family, guest_profile, region, cell)` and snapshots the matched compatibility row id, exact-match key, and row capabilities for that target.
- `promoted_channel` remains only as a legacy derived summary when every persisted publication manifest shares one channel.
- Verification and promotion stay durable and outbox-backed, and promotion is rejected when no exact compatibility row exists for the requested publication target.
