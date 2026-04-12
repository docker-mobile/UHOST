# uhost-svc-netsec

Purpose:

- Own network policies, IP sets, private networks, private connectivity resources, service identities, egress rules, and inspection profiles.
- Record flow-audit evidence for deny-by-default network decisions.

Primary endpoints:

- `GET /netsec`
- `GET/POST /netsec/policies`
- `GET/POST /netsec/ipsets`
- `GET/POST /netsec/private-networks`
- `GET/POST /netsec/private-networks/{private_network_id}/subnets`
- `GET/POST /netsec/private-networks/{private_network_id}/route-tables`
- `GET/POST /netsec/private-networks/{private_network_id}/route-tables/{route_table_id}/routes`
- `GET/POST /netsec/private-networks/{private_network_id}/next-hops`
- `GET/POST /netsec/private-networks/{private_network_id}/service-connect-attachments`
- `GET/POST /netsec/private-networks/{private_network_id}/nat-gateways`
- `GET/POST /netsec/private-networks/{private_network_id}/transit-attachments`
- `GET/POST /netsec/private-networks/{private_network_id}/vpn-connections`
- `GET/POST /netsec/private-networks/{private_network_id}/peerings`
- `GET/POST /netsec/service-identities`
- `GET/POST /netsec/egress-rules`
- `GET/POST /netsec/inspection-profiles`
- `GET /netsec/summary`
- `GET /netsec/flow-audit`
- `GET /netsec/flow-audit/summary`
- `POST /netsec/policy-verify`
- `GET /netsec/outbox`

State files:

- `netsec/policies.json`
- `netsec/ip_sets.json`
- `netsec/private_networks.json`
- `netsec/subnets.json`
- `netsec/route_tables.json`
- `netsec/routes.json`
- `netsec/next_hops.json`
- `netsec/service_connect_attachments.json`
- `netsec/nat_gateways.json`
- `netsec/transit_attachments.json`
- `netsec/vpn_connections.json`
- `netsec/peerings.json`
- `netsec/service_identities.json`
- `netsec/egress_rules.json`
- `netsec/inspection_profiles.json`
- `netsec/flow_audit.json`
- `netsec/audit.log`
- `netsec/outbox.json`

Operational notes:

- Policy verification stays deny-by-default and records flow-audit evidence for review.
- The service reads abuse quarantine state to tighten network posture for flagged subjects.
