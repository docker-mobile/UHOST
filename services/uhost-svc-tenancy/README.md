# uhost-svc-tenancy

Purpose:

- Own organization, project, and environment hierarchy documents.
- Provide the tenant-scoping backbone used by the rest of the control plane.

Primary endpoints:

- `GET /tenancy`
- `GET /tenancy/billing-links`
- `GET/POST /tenancy/organizations`
- `GET/POST /tenancy/projects`
- `GET/POST /tenancy/environments`
- `GET /tenancy/summary`

State files:

- `tenancy/organizations.json`
- `tenancy/projects.json`
- `tenancy/environments.json`
- `tenancy/audit.log`

Operational notes:

- Mutating operations append audit records for organization, project, and environment changes.
- `GET /tenancy/billing-links` projects optional `billing_account_id` relationships so billing ownership can be joined without duplicating tenancy state.
- The hierarchy documents are read back by other bounded contexts for tenant scoping in beta.
