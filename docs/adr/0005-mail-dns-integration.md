# ADR 0005: Mail Domain and DNS Automation Hooks

Status: accepted

Decision:

- Implement `uhost-svc-mail` for domain onboarding, route hooks, retry state machine, and reputation controls.
- Generate DKIM/SPF/DMARC record payloads as versioned events for DNS integration flows.
- Track reputation state per domain and suspend relay when risk thresholds are crossed.

Rationale:

- Mail setup requires coordinated DNS and delivery controls.
- Event-driven auth-record publication keeps DNS provider adapters replaceable.
- Reputation data is needed to close abuse loops with trust-safety systems.

Consequences:

- Mail domain onboarding now emits auth-record sync events.
- Delivery failures can reduce reputation and block outbound relay.
